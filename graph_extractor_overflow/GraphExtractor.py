import os
import re
import numpy as np
# integer overflow vulnerability

# map user-defined variables to symbolic names(var)
var_list = ['balances', 'userBalance[msg.sender]', '[msg.sender]', '[from]', '[to]', 'msg.sender']

# function limit type
function_limit = ['private', 'onlyOwner', 'internal', 'onlyGovernor', 'onlyCommittee', 'onlyAdmin', 'onlyManager',
                  'only_owner', 'onlyProxyOwner', 'ownerExists']

# Boolean condition expression:
var_op_bool = ['~', '**', '!=', '<', '>', '<=', '>=', '<<=', '>>=', '==', '<<', '>>', '||', '&&']

# Assignment expressions
var_op_assign = ['|=', '&=', '+=', '-=', '*=', '/=', '%=', '++', '--', '=']

# function call restrict
core_call_restrict = ['NoLimit', 'LimitedAC']

def split_function(filepath):
    function_list = []
    contract_list = []  # Important statements stored outside of functions
    f = open(filepath, 'r', encoding='utf-8')  
    lines = f.readlines()
    f.close()

    flag = -1
    flag1 = 0

    for line in lines:
        text = line.strip()
        if len(text) > 0 and text != "\n":
            if text.split()[0] == "function" and len(function_list) > 0:
                flag1 = 0

        if flag1 == 0:
            if len(text) > 0 and text != "\n":
                if text.split()[0] == "function" or text.split()[0] == "function()":  
                    function_list.append([text])
                    flag += 1
                elif "pragma solidity" in text or text.strip(' ').startswith("library") or text.strip(
                        ' ').startswith("contract") or text.strip(' ').startswith("constructor") or text.strip(
                    ' ').startswith("modifier") or text.strip(
                    ' ').startswith("interface") or text.strip(' ') == ("_;") or text.strip(' ') == ("}"):
                    continue
                elif len(function_list) > 0 and ("function" in function_list[flag][0]): 
                    if text.split()[0] != "modifier" and text.split()[0] != "event" and text.split()[
                        0] != "contract" and text.split()[0] != "constructor" and text.split()[0] != "interface" and \
                            text.split()[0] != "library":
                        function_list[flag].append(text)
                    else:
                        flag1 += 1
                        contract_list.append(text)
                        continue
                else:
                    contract_list.append(text)
        else:
            if "pragma solidity" in text or text.strip(' ').startswith("library") or text.strip(
                    ' ').startswith("contract") or text.strip(' ').startswith("constructor") or text.strip(
                ' ').startswith("modifier") or text.strip(
                ' ').startswith("interface") or text.strip(' ') == ("_;") or text.strip(' ') == ("}"):
                continue
            else:
                contract_list.append(text)

    function_list.append(contract_list)
    return function_list

def exist_safemath(filepath):
    f = open(filepath, 'r', encoding='utf-8') 
    lines = f.readlines()
    f.close()

    for line in lines:
        text = line.strip()
        if text.strip(' ').startswith("library SafeMath"):
            return 1

    return 0

# Position the call.value to generate the graph
def generate_graph(filepath):

    overList = []
    otherFunctionList = []  # Store functions other than W functions
    node_list = []  # Store all the points
    edge_list = []  # Store edge and edge features
    node_feature_list = []  # Store nodes feature
    overFlag = 0

    allFunctionList = split_function(filepath)  # Store all functions

    for i in range(len(allFunctionList)):
        flag = 0
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if ('+' in text or '*' in text or '-' in text) and '= ' in text and 'for' not in text and '==' not in text and '>=' not in text  and '<=' not in text:
                overList.append(allFunctionList[i])
                flag += 1
                break
        if flag == 0:
            otherFunctionList.append(allFunctionList[i])

    # ======================================================================
    # ---------------------------  store S and W    ------------------------
    # ======================================================================
    for i in range(len(overList)):
        node_list.append("S" + str(i))
        node_list.append("W" + str(i))
        overFlag += 1

        limit_count = 0
        for k in range(len(function_limit)):
            if function_limit[k] in overList[i][0]:
                limit_count += 1
                node_feature_list.append(
                    ["S" + str(i), "LimitedAC", ["W" + str(i)], 2])
                node_feature_list.append(
                    ["W" + str(i), "LimitedAC", ["NULL"], 1])
                edge_list.append(["W" + str(i), "S" + str(i), 1, 'FW'])
                break
            elif k + 1 == len(function_limit) and limit_count == 0:
                node_feature_list.append(
                    ["S" + str(i), "NoLimit", ["W" + str(i)], 2])
                node_feature_list.append(
                    ["W" + str(i), "NoLimit", ["NULL"], 1])

            edge_list.append(["W" + str(i), "S" + str(i), 1, 'FW'])

    # ======================================================================
    # ---------------------------  store var nodes  ------------------------
    # ======================================================================
    for i in range(len(overList)):
        overFlag1 = 0
        overFlag2 = 0
        Varover = None
        varFlag = 0
        varlist=[]

        for j in range(len(overList[i])):
            text = overList[i][j]
            if ('+' in text or '*' in text or '-' in text) and '= ' in text and 'for' not in text and '==' not in text and '>=' not in text  and '<=' not in text:
                overFlag1 += 1
                Varover = text.split('=')[0].strip('+').strip('*').strip()
                if ' ' in Varover:
                    Varover = Varover.split(' ')[-1]  #Variables that may overflow

                node_list.append("VAR" + str(varFlag))
                varFlag += 1

                var_node = 0
                for a in range(len(var_op_assign)):
                    if var_op_assign[a] in text:
                        node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'warning'])
                        var_node += 1
                        break
                if var_node == 0:
                    node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'compliance'])


                if "return" in text:
                    node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'violation'])
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'RE'])
                    node_list.append("VAR" + str(varFlag))
                    varFlag += 1
                    break

                elif "assert" in text:
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'AH'])
                elif "require" in text:
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'RG'])
                elif "if" in text:
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'IF'])
                elif "for" in text:
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'FOR'])
                else:
                    edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'FW'])

    if overFlag == 0:
        print(filepath+":Currently, there is no inter_overflow")

        node_feature_list.append(["S0", "NoLimit", ["NULL"], 0])
        node_feature_list.append(["W0", "NoLimit", ["NULL"], 0])
        node_feature_list.append(["VAR0", "NULL", 0, "compliance"])
        edge_list.append(["W0", "S0", 0, 'FW'])
        edge_list.append(["S0", "VAR0", 0, 'FW'])

    # Handling some duplicate elements, the filter leaves a unique
    edge_list = list(set([tuple(t) for t in edge_list]))
    edge_list = [list(v) for v in edge_list]
    node_feature_list_new = []
    [node_feature_list_new.append(i) for i in node_feature_list if not i in node_feature_list_new]

    return node_feature_list_new, edge_list


def printResult(file, node_feature, edge_feature):

    for i in range(len(node_feature)):
        if 'W' in node_feature[i][0] or 'S' in node_feature[i][
            0]:  
            for j in range(0, len(node_feature[i][2]), 2):
                if j + 1 < len(node_feature[i][2]):
                    tmp = node_feature[i][2][j] + "," + node_feature[i][2][j + 1]
                elif len(node_feature[i][2]) == 1:
                    tmp = node_feature[i][2][j]

            node_feature[i][2] = tmp

    nodeOutPath="../test/overflow/node/" + file
    edgeOutPath = "../test/overflow/edge/" + file

    f_node = open(nodeOutPath, 'a')#w
    for i in range(len(node_feature)):
        result = " ".join(np.array(node_feature[i]))
        f_node.write(result + '\n')
    f_node.close()

    f_edge = open(edgeOutPath, 'a')
    for i in range(len(edge_feature)):
        result = " ".join(np.array(edge_feature[i]))
        f_edge.write(result + '\n')
    f_edge.close()


if __name__ == "__main__":
    inputFileDir = "../test/allsourcecode/"
    inputtxt = open("../test/overflow/name.txt", 'r')
    #dirs = os.listdir(inputFileDir)

    for line in inputtxt.readlines():
        inputFilePath = inputFileDir + line.strip('\n')+'.sol'
        if inputFilePath == '../test/allsourcecode/17542.sol':
             print('nbkbkhbhkb')
        node_feature, edge_feature = generate_graph(inputFilePath)
        node_feature = sorted(node_feature, key=lambda x: (x[0]))
        edge_feature = sorted(edge_feature, key=lambda x: (x[2], x[3]))
        printResult(line.strip('\n')+'.sol', node_feature, edge_feature)
