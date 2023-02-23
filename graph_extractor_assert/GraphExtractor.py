import os
import re
import numpy as np
# assert violation vulnerability

# map user-defined variables to symbolic names(var)
var_list = ['balances[msg.sender]', 'participated[msg.sender]', 'playerPendingWithdrawals[msg.sender]',
            'nonces[msgSender]', 'balances[beneficiary]', 'transactions[transactionId]', 'tokens[token][msg.sender]',
            'totalDeposited[token]', 'tokens[0][msg.sender]', 'accountBalances[msg.sender]', 'accountBalances[_to]',
            'creditedPoints[msg.sender]', 'balances[from]', 'withdrawalCount[from]', 'balances[recipient]',
            'investors[_to]', 'Bal[msg.sender]', 'Accounts[msg.sender]', 'Holders[_addr]', 'balances[_pd]',
            'ExtractDepositTime[msg.sender]', 'Bids[msg.sender]', 'participated[msg.sender]', 'deposited[_participant]',
            'Transactions[TransHash]', 'm_txs[_h]', 'balances[investor]', 'this.balance', 'proposals[_proposalID]',
            'accountBalances[accountAddress]', 'Chargers[id]', 'latestSeriesForUser[msg.sender]',
            'balanceOf[_addressToRefund]', 'tokenManage[token_]', 'milestones[_idMilestone]', 'payments[msg.sender]',
            'rewardsForA[recipient]', 'userBalance[msg.sender]', 'credit[msg.sender]', 'credit[to]', 'round_[_rd]',
            'userPendingWithdrawals[msg.sender]', '[msg.sender]', '[from]', '[to]', '[_to]', "msg.sender"]

global_val = {'bool', 'struct', 'int', 'uint', 'address', 'ActionChoices', 'string'}

# function limit type
function_limit = ['private', 'onlyOwner', 'internal', 'onlyGovernor', 'onlyCommittee', 'onlyAdmin', 'onlyPlayers',
                  'onlyManager', 'onlyHuman', 'only_owner', 'onlyCongressMembers', 'preventReentry', 'onlyMembers',
                  'onlyProxyOwner', 'ownerExists', 'noReentrancy', 'notExecuted', 'noReentrancy', 'noEther',
                  'notConfirmed']

# Boolean condition expression:
var_op_bool = ['!', '~', '**', '*', '!=', '<', '>', '<=', '>=', '==', '<<=', '>>=', '<<', '>>', '||', '&&']

# Assignment expressions
var_op_assign = ['|=', '=', '^=', '&=', '<<=', '>>=', '+=', '-=', '*=', '/=', '%=', '++', '--']

global_val = {'bool', 'int', 'uint', 'address ', 'address[] ', 'string', 'ContractParam', 'enum', 'fixed', 'ufixed',
              'bytes'}  # struct mapping

val_limit = {'public', 'private', 'internal', 'external'}


# split all functions of contracts
def split_function(filepath):
    function_list = []
    contract_list = []  # Important statements stored outside of functions
    f = open(filepath, 'r', encoding='utf-8')  
    lines = f.readlines()
    f.close()

    flag = -1
    flag1 = 0
    flag_li = 0

    for line in lines:
        text = line.strip()
        # Remove the special code：version library
        if "pragma solidity" in text or text == ("_;") or text == ("{") or text == ("}"):
            continue

        if text.startswith("library "):
            flag_li = 1
            continue

        if text.startswith("contract ") or text.startswith("interface "):
            flag_li = 0
            continue

        if flag_li == 0:
            if len(text) > 0 and text != "\n":
                if text.startswith("function"):
                    flag1 = 0

            if flag1 == 0:
                if len(text) > 0 and text != "\n":
                    if text.startswith("function"):  # starts with function
                        function_list.append([text])
                        flag += 1
                    elif text.startswith("constructor") or text.startswith("interface"):
                        continue

                    elif len(function_list) > 0 and ("function" in function_list[flag][0]):  # contents of a function
                        if not text.startswith("modifier") and not text.startswith("event") and not text.startswith("constructor"):
                            function_list[flag].append(text)
                        else:
                            flag1 += 1
                            contract_list.append(text)
                            continue
                    else:
                        contract_list.append(text)
            else:
                contract_list.append(text)

    function_list.append(contract_list)
    return function_list

def generate_graph(filepath):
    allFunctionList = split_function(filepath)  # Store all functions

    # assertList, assertName = Filter_vulnerability_function(allFunctionList, contract_list)
    assertList = []
    assertName = []
    assertName1 = []
    assertName2 = []
    node_list = []  # Store all the points
    edge_list = []  # Store edge and edge features
    node_feature_list = []  # Store nodes feature
    assertFlag = 0

    for i in range(len(allFunctionList)):
        f_a_n=0
        flag = 0
        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            if 'assert' in text:
                if f_a_n==0:
                    assertList.append(allFunctionList[i]) 
                    f_a_n = 1

                tt=re.findall(r'[(](.*)[)]', text)# variable or formula
                tt_op={' = ','==','> ','< ','>=','<='}
                for t in tt:
                    fop = 0
                    for op in tt_op:
                        if op in t:
                            fop=1
                            assertName2.extend(t.split(op))
                            break
                    if fop==0:
                        assertName2.append(t)

                flag += 1
    assertName1= [x for x in assertName2 if x]  # Remove empty x
    [assertName.append(i) for i in assertName1 if not i in assertName]  # Remove duplicate x

    # ======================================================================
    # ---------------------------  store S and W    ------------------------
    # ======================================================================
    for i in range(len(assertList)):
        node_list.append("S" + str(i))
        node_list.append("W" + str(i))
        assertFlag += 1
        limit_count = 0
        for k in range(len(function_limit)):
            if function_limit[k] in assertList[i][0]:
                limit_count += 1
                node_feature_list.append(
                    ["S" + str(i), "LimitedAC", ["W" + str(i)], 2])
                node_feature_list.append(
                    ["W" + str(i), "LimitedAC", ["NULL"], 1])
                edge_list.append(["W" + str(i), "S" + str(i), 1, 'FW'])
                break

        if limit_count == 0:
            node_feature_list.append(
                ["S" + str(i), "NoLimit", ["W" + str(i)], 2])
            node_feature_list.append(
                ["W" + str(i), "NoLimit", ["NULL"], 1])

            edge_list.append(["W" + str(i), "S" + str(i), 1, 'FW'])

    # ======================================================================
    # ---------------------------  store var nodes  ------------------------
    # ======================================================================

    for i in range(len(allFunctionList)):  # global search for status changes of name
        assertFlag1 = 0
        assertFlag2 = 0
        Varassert = None
        varFlag = 0

        for j in range(len(allFunctionList[i])):
            text = allFunctionList[i][j]
            for name in assertName:
                # Data flow extraction and Control flow extraction
                name=name.strip('!').strip()
                print(name)

                if ' '+name+' ' in text:
                    name=' '+name
                    if name in text.split(' = ')[0] and ' = ' in text:
                        assertFlag1 += 1

                        var_node = 0
                        for a in range(len(var_op_assign)):
                            if var_op_assign[a] in text:
                                node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'warning'])
                                var_node += 1
                                break
                        if var_node == 0:
                            node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'compliance'])

                        node_list.append("VAR" + str(varFlag))
                        varFlag += 1

                    
                    if 'return' in text:
                        node_feature_list.append(["VAR" + str(varFlag), "S" + str(i), 3, 'violation'])
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'RE'])
                        node_list.append("VAR" + str(varFlag))
                        varFlag += 1
                    elif "assert" in text:
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'AH'])
                        varFlag += 1
                    elif "require" in text:
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'RG'])
                        varFlag += 1
                    elif "if" in text:
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'IF'])
                        varFlag += 1
                    elif "for" in text:
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'FOR'])
                        varFlag += 1
                    else:
                        edge_list.append(["S" + str(i), "VAR" + str(varFlag), 2, 'FW'])

    if assertFlag == 0:
        print(filepath + ":Currently, there is no key word assert")

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

    nodeOutPath = "../test/assert/node/" + file
    edgeOutPath = "../test/assert/edge/" + file

    f_node = open(nodeOutPath, 'a')
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
    inputtxt = open("../test/assert/name.txt", 'r')

    for line in inputtxt.readlines():
        inputFilePath = inputFileDir + line.strip('\n')
        inputFilePath = inputFileDir + line.strip('\n')
        node_feature, edge_feature = generate_graph(inputFilePath) 
        node_feature = sorted(node_feature, key=lambda x: (x[0]))
        edge_feature = sorted(edge_feature, key=lambda x: (x[2], x[3]))
        printResult(line.strip('\n'), node_feature, edge_feature)
        print(line.strip('\n') + ':End of execution')

    # test_contract = "../test/40000sourcecode/1001.sol"
    # file = test_contract.split('.sol')[0].split('/')[-1] + '.sol'
    # node_feature, edge_feature = generate_graph(test_contract)
    # node_feature = sorted(node_feature, key=lambda x: (x[0]))
    # edge_feature = sorted(edge_feature, key=lambda x: (x[2], x[3]))
    # printResult(file, node_feature, edge_feature)
