#!/usr/bin/env python
from src.data_pipeline import download_and_process_apks
from tqdm import tqdm
from scipy.sparse import csr_matrix
import sys, json, stat, os, scipy.sparse, networkx as nx, gc

def main(targets, test=False):
    if targets[0] not in ['data', 'data-test']:
        raise Error('Unknown target')

    with open('config/test-params.json', 'r') as config_file:
        config = json.load(config_file)

    if 'lines_per_file' not in config:
        config['lines_per_file'] = 200
    if 'files_per_app' not in config:
        config['files_per_app'] = 100

    # if targets[0] == 'data':
    #     download_and_process_apks(config['download_amount'], \
    #             config['visit_probability'], config['download_probability'], \
    #             config['size_limit'], config['base_url'])
    if targets[0] == 'data-test':
        print("Running apktool on sample.apk")
        os.system('apktool d -r -b -f --no-assets -o src/data-test sample.apk')
        print("Deleting non-smali files from data-test")
        os.system('find data-test -type f -not -name "*.smali" -exec rm -f {} \;')

    if len(targets) == 2 and targets[1] == 'process':
        if targets[0] == 'data':
            return process(config)
        elif targets[0] == 'data-test':
            print("Running process target on data-test with config.json parameters")
            return process(config, True)


def process(config, test=False):
    api_list = []
    app_list = []
    package_list = []
    seen_api = set()

    app_to_api = nx.Graph()
    api_cooccur = nx.Graph()
    api_same_invoke = nx.Graph()
    api_same_package = nx.Graph()

    for directory in (tqdm(next(os.walk(config['path_benign']))[1] + next(os.walk(config['path_malware']))[1]) if not test else ['data-test']):
        app_list.append(directory)
        app_to_api.add_node(directory)

        for subdir, dirs, files in os.walk((config['path_benign'] + '/' + directory if not test else 'data-test')):
            for i, file in enumerate(files):
                if config['files_per_app'] and config['files_per_app'] == i:
                    break

                filepath = subdir + os.sep + file

                with open(filepath, 'r') as fp:
                    api_calls = set()

                    for j, line in enumerate(fp):
                        if config['lines_per_file'] and config['lines_per_file'] == j:
                            break
                        stripped = line.strip()
                        if stripped == '.end method':
                            api_calls.clear()
                        if stripped[:6] == 'invoke':
                            invoke_method = stripped.split(' {')[0][7:].split('/')[0]
                            splitted = line.split('}, ')
                            fns = splitted[1].split('->')
                            api_package = fns[0]
                            method = fns[1].split('(')[0]

                            current_method_call = api_package + ',' + method

                            api_calls.add(current_method_call)

                            if current_method_call not in seen_api:
                                api_list.append(current_method_call)
                                seen_api.add(current_method_call)

                            # app to api generation
                            if current_method_call not in app_to_api:
                                app_to_api.add_node(current_method_call)
                            app_to_api.add_edge(directory, current_method_call)

                            # api to api co-occurance generation
                            if current_method_call not in api_cooccur:
                                api_cooccur.add_node(current_method_call)
                            for api_call in api_calls:
                                if not api_cooccur.has_edge(current_method_call, api_call):
                                    api_cooccur.add_edge(current_method_call, api_call)

                            if invoke_method not in api_same_invoke:
                                api_same_invoke.add_node(invoke_method)
                            if current_method_call not in api_same_invoke:
                                api_same_invoke.add_node(current_method_call)
                            if not api_same_invoke.has_edge(invoke_method, current_method_call):
                                api_same_invoke.add_edge(invoke_method, current_method_call)

                            if api_package not in api_same_package:
                                package_list.append(api_package)
                                api_same_package.add_node(api_package)
                            if current_method_call not in api_same_package:
                                api_same_package.add_node(current_method_call)
                            if not api_same_package.has_edge(api_package, current_method_call):
                                api_same_package.add_edge(api_package, current_method_call)

    del seen_api
    matrix_A = nx.adjacency_matrix(app_to_api, api_list + app_list)[-len(app_list):, :-len(app_list)]
    scipy.sparse.save_npz('matrix_A.npz', matrix_A)
    print("A matrix saved")
    del matrix_A, app_to_api, app_list
    matrix_B = nx.adjacency_matrix(api_cooccur, api_list)
    scipy.sparse.save_npz('matrix_B.npz', matrix_B)
    print("B matrix saved")
    del matrix_B, api_cooccur
    matrix_I = nx.adjacency_matrix(api_same_package, nodelist=api_list + package_list)[-len(package_list):, :-len(package_list)]
    matrix_I = matrix_I.transpose() @ matrix_I
    scipy.sparse.save_npz('matrix_I.npz', matrix_I)
    print("I matrix saved")
    del matrix_I, package_list, api_same_package
    gc.collect()
    # do api-api same-invoke last, takes up most memory
    matrix_P = nx.adjacency_matrix(api_same_invoke, nodelist=api_list + config['invoke_types'])[-len(config['invoke_types']):, :-len(config['invoke_types'])]
    matrix_P = matrix_P.transpose() @ matrix_P
    scipy.sparse.save_npz('matrix_P.npz', matrix_P)
    print("P matrix saved")

if __name__ == '__main__':
    os.chmod('process-app.sh', stat.S_IRWXU)
    if len(sys.argv) != 3:
        raise Error('Targets length must equal 2')
    main(sys.argv[1:])
