import pickle
import os

forwarded_resps = []
dropped_resps = []
reqs = []
req_times = {}
legit_resps = []
broadcasts = [0]
install_pkts = [0]

def count_broadcasts():
    broadcasts[0] += 1

def count_installs():
    install_pkts[0] += 1

def track_reqs(id, src, dst, timestamp):
    reqs.append([id, src, dst])
    req_times[(id, src, dst)] = timestamp

def check_if_need_to_retransmit(id, src, dst, timestamp):
    if [id, dst, src] in reqs:
        idx = reqs.index([id, dst, src])
        legit_resps.append([id, dst, src, req_times[(id, dst, src)], timestamp])
        reqs.pop(idx)
        del req_times[(id, dst, src)]

def forwarded(id, src, dst, timestamp):
    if id == 0 and src == 0 and dst == 0:
        return
    forwarded_resps.append([id, dst, src, timestamp])

def dropped(id, src, dst, timestamp):
    if id == 0 and src == 0 and dst == 0:
        return
    dropped_resps.append([id, src, dst, timestamp])

def write_to_file():
    global forwarded_resps
    global dropped_resps
    global broadcasts
    global install_pkts
    with open('forwarded_tmp.pkl','wb') as f:
        pickle.dump(forwarded_resps,f)
    with open('dropped_tmp.pkl','wb') as f:
        pickle.dump(dropped_resps,f)
    with open('broadcasts_tmp.pkl','wb') as f:
        pickle.dump(broadcasts[0],f)
    with open('installs_tmp.pkl','wb') as f:
        pickle.dump(install_pkts[0],f)
    forwarded_resps = []
    dropped_resps = []
    broadcasts = [0]
    install_pkts = [0]
    os.replace('forwarded_tmp.pkl', 'forwarded.pkl')
    os.replace('dropped_tmp.pkl', 'dropped.pkl')
    os.replace('broadcasts_tmp.pkl', 'broadcasts.pkl')
    os.replace('installs_tmp.pkl', 'installs.pkl')


def write_retransmissions_to_file():
    global legit_resps
    global reqs
    with open('retransmissions.pkl','wb') as f:
        pickle.dump(legit_resps,f)
    legit_resps = []
    reqs = []

