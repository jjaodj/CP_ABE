from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
import charm.core.math.pairing as pg
from charm.config import libs, pairing_lib
import base64
import json
import mysql.connector
import re
import jsonpickle
from flask import Flask, request, make_response, jsonify
import hashlib
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairingcurves import params as param_info
import pickle

from charm.core.engine.util import objectToBytes,bytesToObject

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2 }


debug = False
class CPabe_BSW07(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe_BSW07(group)
    >>> msg = group.random(GT)
    >>> attributes = ['ONE', 'TWO', 'THREE']
    >>> access_policy = '((four or three) and (three or one))'
    >>> (master_public_key, master_key) = cpabe.setup()
    >>> secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> msg == decrypted_msg
    True
    """ 
        
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
       
        g.initPP(); gp.initPP()
        
        h = g ** beta; f = g ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        
        pk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'e_gg_alpha':e_gg_alpha }
        mk = {'beta':beta, 'g2_alpha':gp ** alpha }
        return (pk, mk)
    
    @Input(pk_t, mk_t, [str])
    @Output(sk_t)
    def keygen(self, pk, mk, S):
        r = group.random() 
        g_r = (pk['g2'] ** r)    
        D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])        
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        return { 'D':D, 'Dj':D_j, 'Djp':D_j_pr, 'S':S }
    
    @Input(pk_t, GT, str)
    @Output(ct_t)
    def encrypt(self, pk, M, policy_str): 
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)      

        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i] 
        
        return { 'C_tilde':(pk['e_gg_alpha'] ** s) * M,
                 'C':C, 'Cy':C_y, 'Cyp':C_y_pr, 'policy':policy_str, 'attributes':a_list }
    
    @Input(pk_t, sk_t, ct_t)
    @Output(GT)

    def decrypt(self, pk, sk, ct):
    
    
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]
    		
        return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)


def trann(filename,p1,p2): 

	groupObj = PairingGroup('SS512')
	cpabe = CPabe_BSW07(groupObj) 
	attrs = [str(p1),str(p2)]
	access_policy = '(' + str(p1) + ' or ' + str(p2) + ')'
	if debug:
		print("Attributes =>", attrs); print("Policy =>", access_policy)

	(pk, mk) = cpabe.setup()

	sk = cpabe.keygen(pk, mk, attrs)
				    
	rand_msg= groupObj.random(GT)
	
	msg = hashlib.sha256(str(rand_msg).encode('utf-8')).digest()
	a=base64.b64encode(msg).decode('utf-8')
				    
	ct = cpabe.encrypt(pk, rand_msg, access_policy)
	
	ct_bytes = objectToBytes(ct, groupObj)
	ct_path = '/home/duy/Desktop/CT/'+filename+'.bin'
	with open(ct_path, 'wb') as file:
		file.write(ct_bytes)
	
	pk_bytes= objectToBytes(pk, groupObj)
	pk_path = '/home/duy/Desktop/PK/'+filename+'.bin'
	with open(pk_path, 'wb') as file:
		file.write(pk_bytes)
		
	sk_bytes = objectToBytes(sk, groupObj)
	sk_path = '/home/duy/Desktop/SK/'+filename+'.bin'
	with open(sk_path, 'wb') as file:
		file.write(sk_bytes)
	
	mk_bytes = objectToBytes(mk, groupObj)
	mk_path = '/home/duy/Desktop/MK/'+filename+'.bin'
	with open(mk_path, 'wb') as file:
		file.write(mk_bytes)
		
		########
	print("rand_msg",rand_msg)
	print("key",msg)	

	return a
	
app = Flask(__name__)
@app.route('/api/download', methods=['POST','GET'])
def chan():
	data = request.get_json()
	print(data)
    	
	filename = data['FileName']
	ct_path='/home/duy/Desktop/CT/'+filename+'.bin'
	pk_path='/home/duy/Desktop/PK/'+filename+'.bin'
	sk_path='/home/duy/Desktop/SK/'+filename+'.bin'
	mk_path='/home/duy/Desktop/MK/'+filename+'.bin'
	groupObj = PairingGroup('SS512')
	cpabe = CPabe_BSW07(groupObj)
	

	with open(ct_path, 'rb') as file:
		ct_from_file = file.read()
	orig_ct = bytesToObject(ct_from_file, groupObj)
	with open(pk_path, 'rb') as file:
		pk_from_file = file.read()
	orig_pk = bytesToObject(pk_from_file, groupObj)
	with open(sk_path, 'rb') as file:	
		sk_from_file = file.read()
	orig_sk = bytesToObject(sk_from_file, groupObj)
	with open(mk_path, 'rb') as file:
		mk_from_file = file.read()
	orig_mk = bytesToObject(mk_from_file, groupObj)


	rec_msg = cpabe.decrypt(orig_pk,orig_sk,orig_ct)
	msg = hashlib.sha256(str(rec_msg).encode('utf-8')).digest()
	a=base64.b64encode(msg).decode('utf-8')
	print("rec_msg",rec_msg)
	print("key1",msg)
	print(a)
	response = make_response(jsonify({'key': a}))
	response.headers['Content-Type'] = 'application/json'
	return response

@app.route('/api/key', methods=['POST', 'GET'])
def uploadkey():
    data = request.get_json()
    print(data)
  
    filename = data['FileName']
    p1 = data['MAPHONG']
    p2 = data['POSITION']
    rturn = trann(str(filename),str(p1),str(p2))
    print(rturn)
    response = make_response(jsonify({'key': rturn}))
    response.headers['Content-Type'] = 'application/json'
    return response

if __name__ == "__main__":
    debug = True
    app.run(host='0.0.0.0')
