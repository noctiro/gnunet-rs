"""Finite public-context cases. No invalid C KEM or underflowing one-shot call."""
from collections import Counter
E = bytes([7])*32
R = bytes([5])*32

def token(value):
    return value.hex() or '-'

def row(*values):
    return ' '.join(token(value) if isinstance(value,bytes) else str(value) for value in values)

def setup(mode,op='SETUP',sequence='-',aad=b'aad\0field',data=b'',info=b'info\0context'):
    psk = b'secret\0key' if mode==1 else b''
    identifier = b'identifier\0bytes' if mode==1 else b''
    if op=='SETUP': return row(op,mode,E,R,info,psk,identifier,'-')
    return row(op,mode,E,R,info,psk,identifier,sequence,aad,data)

def base():
    cases=['META']
    for secret in (bytes(32),bytes([255])*32,E,R):cases.append(row('KEY',secret))
    for mode in range(4):
        for psk in (b'',b'psk\0'):
            for identifier in (b'',b'id\0'):
                for info in (b'',b'info\0context'):
                    cases.append(row('SETUP',mode,E,R,info,psk,identifier,'-'))
    for mode in (0,1):
        for length in (0,1,16,65,1024,65535):
            data=bytes((i*37+11)%256 for i in range(length))
            for sequence in (0,1,255,256,2**32-1,2**32,2**64-2,2**64-1):
                cases.append(setup(mode,'ROUND',sequence,data=data))
        for length in (0,3,16):cases.append(setup(mode,'LIMIT_OPEN',2**64-1,data=bytes([17])*length))
        for sequence in (0,2**64-1):cases.append(setup(mode,'WRONG',sequence,data=bytes(16)))
    for length in (0,17,1024):
        data=bytes((i*19+7)%256 for i in range(length))
        cases.append(row('DEFAULT',R,b'info\0context',b'aad\0field',data))
        cases.append(row('ONESHOT',R,b'info\0context',b'aad\0field',data))
    return cases

def failures(cases,outputs):
    if len(cases)!=len(outputs):raise ValueError('C corpus/result row mismatch')
    additions=[]
    for mode in ('0','1'):
        index=next(i for i,line in enumerate(cases) if line.startswith('ROUND '+mode+' ') and line.split()[7]=='0' and len(line.split()[9])==32)
        parts=cases[index].split();observed=outputs[index].split()
        if observed[:2]!=['ROUND','1']:raise ValueError('missing successful real-C source ciphertext')
        cipher=bytearray.fromhex(observed[5]);parts[0]='OPEN';parts[9]=cipher.hex()
        additions.append(' '.join(parts))
        for field in ('cipher','tag','aad','info','sequence','recipient','psk','id'):
            if mode=='0' and field in ('psk','id'):continue
            changed=parts.copy()
            if field in ('cipher','tag'):
                data=cipher.copy();data[0 if field=='cipher' else -1]^=1;changed[9]=data.hex()
            elif field=='sequence':changed[7]='1'
            else:
                slot={'aad':8,'info':4,'recipient':3,'psk':5,'id':6}[field]
                data=bytearray.fromhex(changed[slot]);data[0]^=1;changed[slot]=data.hex()
            additions.append(' '.join(changed))
        for short in (0,1,15):
            changed=parts.copy();changed[9]=token(bytes(cipher[:short]));additions.append(' '.join(changed))
    return additions

def summary(rows):return dict(sorted(Counter(line.split()[0] for line in rows).items()))
