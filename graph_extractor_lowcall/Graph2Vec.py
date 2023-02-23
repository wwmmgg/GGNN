import os
import json
import numpy as np
from graph_extractor_lowcall.vec2onehot import vec2onehot
from sklearn.decomposition import TruncatedSVD

"""
Node self property + Incoming Var + Outgoing Var + Incoming Edge + Outgoing Edge
"""
dict_AC = {"NULL": 0, "LimitedAC": 1, "NoLimit": 2}

dict_NodeName = {"NULL": 0, "VAR0": 1, "VAR1": 2, "VAR2": 3, "VAR3": 4, "VAR4": 5, "VAR5": 6, "S0": 7,"S1": 8, "S2": 9,
                 "S3": 10,"S4": 11,"S5": 12,"S6": 13, "S7": 14,"S8": 15,"S9": 16,"S10": 16,"W0": 17,"W1": 18, "W2": 19, "W3": 20,
                 "W4": 21, "W5": 22,"W6": 23, "W7": 24, "W8": 25, "W9": 26,"W10": 26,"C0": 27, "C1": 28, "C2": 29, "C3": 30, "C4": 31}

dict_VarOpName = {"NULL": 0, "BOOL": 1, "ASSIGN": 2}

dict_EdgeOpName = {"NULL": 0, "FW": 1, "IF": 2, "GB": 3, "GN": 4, "WHILE": 5, "FOR": 6, "RE": 7, "AH": 8, "RG": 9,
                   "RH": 10, "IT": 11}

dict_AllOpName = {"NULL": 0, "FW": 1, "ASSIGN": 2, "BOOL": 3, "IF": 4, "GB": 5, "GN": 6, "WHILE": 7, "FOR": 8, "RE": 9,
                  "AH": 10, "RG": 11, "RH": 12, "IT": 13}

dict_NodeOpName = {"NULL": 0, "MSG": 1, "INNADD": 2}

dict_ConName = {"NULL": 0, "ARG1": 1, "ARG2": 2, "ARG3": 3, "CON1": 4, "CON2": 5, "CON3": 6, "CNS1": 7, "CNS2": 8,
                "CNS3": 9}

node_convert = {"S0": 0, "S1": 1, "S2": 2,"S3": 3,"S4": 4,"S5": 5,"S6": 6, "S7": 7,"S8": 8,"S9": 9,"S10": 9, "W0": 10, "C0": 11,
                "W1": 12, "C1": 13, "W2": 14, "C2": 15,"W3": 16, "C3": 17,"W4": 18,"C4": 19,"W5": 20,"W6": 21, "W7": 22,
                "W8": 23, "W9": 24,"W10": 24,
                "VAR0": 0, "VAR1": 1,"VAR2": "VAR2", "VAR3": "VAR3", "VAR4": "VAR4", "VAR5": "VAR5"}

dict_MarkName = {"compliance": 0, "warning": 1, "violation": 2}

v2o = vec2onehot()  # create the one-bot dicts


# extract the features of each node from input file #
def extract_node_features(nodeFile):
    nodeNum = 0
    node_list = []
    node_attribute_list = []

    f = open(nodeFile+'.sol')
    lines = f.readlines()
    f.close()

    for line in lines:
        node = list(map(str, line.split()))
        verExist = False
        for i in range(0, len(node_list)):
            if node[0] == node_list[i]:
                verExist = True
            else:
                continue
        if verExist is False:
            node_list.append(node[0])
            nodeNum += 1
        node_attribute_list.append(node)

    return nodeNum, node_list, node_attribute_list

def map_num(ss):
    num=0
    if ss=='NULL':
        num=0
    elif 'VAR' in ss:
        num = 4 + int(ss[3:])
    elif 'S' in ss:
        num = 8 + int(ss[1:])
    elif 'W' in ss:
        num = 12 + int(ss[1:])
    elif 'C' in ss:
        num = 16 + int(ss[1:])

    return num

def map_num1(ss):
    num1 = 0
    if ss=='VAR0':
        num1=0
    elif ss=='VAR1':
        num1 = 1
    elif 'VAR' in ss:
        return ss
    elif 'S' in ss:
        num1 = 5 + int(ss[1:])
    elif 'W' in ss:
        num1 = 10 + int(ss[1:])
    elif 'C' in ss:
        num1 = 11 + int(ss[1:])

    return num1

def embedding_node(node_attribute_list):
    # embedding each node after elimination #
    node_encode = []
    var_encode = []
    node_embedding = []
    var_embedding = []

    for j in range(0, len(node_attribute_list)):
        v = node_attribute_list[j][0]
        if 'S' in v or 'W' in v:
            vf0 = node_attribute_list[j][0]
            vf1 =map_num(str(node_attribute_list[j][0]))
            vfm1 = v2o.node2vecEmbedding(node_attribute_list[j][0])
            vf2 = dict_AC[node_attribute_list[j][1]]
            vfm2 = v2o.nodeAC2vecEmbedding(node_attribute_list[j][1])
            vf3 = map_num(str(node_attribute_list[j][2]))
            vfm3 = v2o.node2vecEmbedding(node_attribute_list[j][2])
            vf4 = int(node_attribute_list[j][3])
            vfm4 = v2o.sn2vecEmbedding(node_attribute_list[j][3])
            nodeEmbedding = vfm1.tolist() + vfm2.tolist() + vfm3.tolist() + vfm4.tolist()
            node_embedding.append([vf0, np.array(nodeEmbedding)])
            temp = [vf1, vf2, vf3, vf4]
            node_encode.append([vf0, temp])
        else:
            vf0 = node_attribute_list[j][0]
            vf1 = map_num(str(node_attribute_list[j][0]))
            vfm1 = v2o.node2vecEmbedding(node_attribute_list[j][0])
            vf2 = map_num(str(node_attribute_list[j][1]))
            vfm2 = v2o.node2vecEmbedding(node_attribute_list[j][1])
            vf3 = int(node_attribute_list[j][2])
            vfm3 = v2o.sn2vecEmbedding(node_attribute_list[j][2])
            vf4 = dict_MarkName[node_attribute_list[j][3]]
            vfm4 = v2o.mark2vecEmbedding(node_attribute_list[j][3])
            varEmbedding = vfm1.tolist() + vfm2.tolist() + vfm3.tolist() + vfm4.tolist()
            var_embedding.append([vf0, np.array(varEmbedding)])
            temp = [vf1, vf2, vf3, vf4]
            var_encode.append([vf0, temp])

    return node_encode, var_encode, node_embedding, var_embedding


def elimination_edge(edgeFile):
    # eliminate edge #
    edge_list = []  # all edge
    extra_edge_list = []  # eliminated edge

    f = open(edgeFile+'.sol')
    lines = f.readlines()
    f.close()

    for line in lines:
        edge = list(map(str, line.split()))
        edge_list.append(edge)

    # The ablation of multiple edge between two nodes, taking the edge with the edge_operation priority
    for k in range(0, len(edge_list)):
        if k + 1 < len(edge_list):
            start1 = edge_list[k][0]  # start node
            end1 = edge_list[k][1]  # end node
            op1 = edge_list[k][3]
            start2 = edge_list[k + 1][0]
            end2 = edge_list[k + 1][1]
            op2 = edge_list[k + 1][3]
            if start1 == start2 and end1 == end2:
                op1_index = dict_EdgeOpName[op1]
                op2_index = dict_EdgeOpName[op2]
                # extract edge attribute based on priority
                if op1_index < op2_index:
                    extra_edge_list.append(edge_list.pop(k))
                else:
                    extra_edge_list.append(edge_list.pop(k + 1))

    return edge_list, extra_edge_list


def embedding_edge(edge_list):
    # extract & embedding the features of each edge from input file #
    edge_encode = []
    edge_embedding = []

    for k in range(len(edge_list)):
        start = edge_list[k][0]  # start node
        end = edge_list[k][1]  # end node
        a, b = edge_list[k][2], edge_list[k][3]

        ef1 = int(a)
        ef2 = dict_EdgeOpName[b]

        ef_temp = [ef1, ef2]
        edge_encode.append([start, end, ef_temp])

        efm1 = v2o.sn2vecEmbedding(a)
        efm2 = v2o.edgeOP2vecEmbedding(b)

        efm_temp = efm1.tolist() + efm2.tolist()
        edge_embedding.append([start, end, np.array(efm_temp)])

    return edge_encode, edge_embedding


def construct_vec(edge_list, node_embedding, var_embedding, edge_embedding, edge_encode):
    # Vec: core/var node + Incoming Edge + Outgoing Edge
    #print("Start constructing node vector...")
    edge_vec_length = len(edge_embedding[0][2])
    edge_in_node = []
    edge_in = []
    edge_out_node = []
    edge_out = []
    node_vec = []
    var_point = ['VAR0']

    for i in range(len(edge_embedding)):
        # The input/output edge vector of VAR0
        if edge_list[i][0] == "VAR0":
            edge_out.append([edge_embedding[i][0], edge_embedding[i][2]])
        elif edge_list[i][1] == "VAR0":
            edge_in.append([edge_embedding[i][1], edge_embedding[i][2]])

    for i in range(len(edge_in)):
        edge_in_node.append(edge_in[i][0])
    for i in range(len(edge_out)):
        edge_out_node.append(edge_out[i][0])

    for i in range(len(var_point)):
        if var_point[i] not in edge_out_node:
            edge_out.append([var_point[i], np.zeros(edge_vec_length, dtype=int)])
        if var_point[i] not in edge_in_node:
            edge_in.append([var_point[i], np.zeros(edge_vec_length, dtype=int)])

    edgeIn_dict = dict(edge_in)
    edgeOut_dict = dict(edge_out)
    var_dict = dict(var_embedding)

    for i in range(len(var_embedding)):
        if var_embedding[i][0] == 'VAR0':
            var_feature_0 = var_dict[var_embedding[i][0]].tolist() + np.array(
                edgeIn_dict[var_embedding[i][0]]).tolist() + \
                            np.array(edgeOut_dict[var_embedding[i][0]]).tolist()
            node_vec.append([var_embedding[i][0], var_feature_0])
            var_embedding[i][1] = var_feature_0

    node_vec_length = len(node_embedding[0][1])
    var_vec_length = len(var_embedding[0][1])

    if node_vec_length > var_vec_length:
        vec_length = node_vec_length
    else:
        vec_length = var_vec_length

    for i in range(len(node_embedding)):
        vec = np.zeros(vec_length, dtype=int)
        vec[0:len(np.array(node_embedding[i][1]))] = np.array(node_embedding[i][1])
        node_embedding[i][1] = vec.tolist()

    for i in range(len(var_embedding)):
        vec = np.zeros(vec_length, dtype=int)
        vec[0:len(np.array(var_embedding[i][1]))] = np.array(var_embedding[i][1])
        var_embedding[i][1] = vec.tolist()

    for i in range(len(node_embedding)):
        node_vec.append([node_embedding[i][0], node_embedding[i][1]])

    # print("Node Vec:")
    for i in range(len(node_vec)):
        node_vec[i][0] = map_num1(node_vec[i][0])

    # "S0": 0, "W0": 1, "VAR0": 2
    #print("Edge Vec:")
    for i in range(len(edge_encode)):
        edge_encode[i][0] = map_num1(edge_encode[i][0])  
        edge_encode[i][1] = map_num1(edge_encode[i][1])  

    graph_edge = []
    for i in range(len(edge_encode)):
        graph_edge.append([edge_encode[i][0], edge_encode[i][2][1], edge_encode[i][1]])

    return node_vec, graph_edge, var_embedding

# svd 
def svd(data):
    tsvd = TruncatedSVD(n_components=5)
    tsvd.fit(data)
    dataMat = tsvd.transform(data)
    return dataMat.round(6).tolist()

if __name__ == "__main__":

    v_path = "../test/lowcall/node/"
    e_path = "../test/lowcall/edge/"

    fullnodes_ouptput_tmp = open("../test/lowcall/fullnodes.json", 'w')

    contract_name = open("../test/lowcall/name.txt")  # contracts list
    contract_label = open("../test/lowcall/label.txt")  # contracts label
    names = contract_name.readline().strip(" ")
    labels = contract_label.readline()

    while names:
        node = os.path.join(v_path, names.strip('\n')+'.sol')
        edge = os.path.join(e_path, names.strip('\n')+'.sol')
        print(names.strip('\n'))

        nodeNum, node_list, node_attribute_list = extract_node_features(node)
        node_encode, var_encode, node_embedding, var_embedding = embedding_node(node_attribute_list)
        edge_list, extra_edge_list = elimination_edge(edge)
        edge_encode, edge_embedding = embedding_edge(edge_list)
        node_vec, graph_edge, var_embedding = construct_vec(edge_list, node_embedding, var_embedding, edge_embedding,
                                                            edge_encode)
        fullnodes_feature_list = []
        for i in range(len(node_embedding)):
            fullnodes_feature_list.append(node_embedding[i][1])
        for i in range(len(var_embedding)):
            fullnodes_feature_list.append(var_embedding[i][1])

        fullnode_graph_dict = ({
            "targets": labels.strip('\n'),
            "graph": graph_edge,  # graph_edge,
            "contract_name": names.strip('\n'),
            "node_features": svd(fullnodes_feature_list),  # corenodes_feature_list
        })

        fullnodes_result = json.dumps(fullnode_graph_dict)

        fullnodes_ouptput_tmp.write(fullnodes_result + "," + "\n")
        names = contract_name.readline()
        labels = contract_label.readline()

fullnodes_ouptput_tmp.close()

