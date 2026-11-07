"""Bounded standard/raw/source-component inputs, not complete UDP owner traffic."""
from collections import Counter

def token(data):return data.hex() or '-'
def row(*values):return ' '.join(token(v) if isinstance(v,bytes) else str(v) for v in values)
def base(nist):
    rows=['META']
    for vector in nist['vectors']:
        data=bytes.fromhex(vector['PT']);a=min(1,len(data));b=min(15,len(data)-a)
        rows.append(row('GCM',bytes.fromhex(vector['Key']),bytes.fromhex(vector['IV']),bytes.fromhex(vector['AAD']),data,a,b))
    for n in (0,1,15,16,17,31,32,63,64,65,104,117,255,1024,65535):
        data=bytes((i*37+7)%256 for i in range(n))
        for aadlen in (0,1,15,16,17,33):
            aad=bytes(range(aadlen));a=min(17,n);b=min(31,n-a)
            rows.append(row('GCM',bytes(range(32)),bytes(range(12)),aad,data,a,b))
    for master in (bytes(32),bytes([7])*32,bytes(range(32))):
        for serial in (0,1,255,256,65535,2**32-1):
            for n in (1,15,16,17,63,104,117,1024,65535):
                if serial==0 and n<104:continue
                data=bytes((i*19+11)%256 for i in range(n))
                a=104 if serial==0 else min(36,n);b=min(13,n-a)
                rows.append(row('UDP',master,serial,data,a,b,'KX' if serial==0 else 'BOX',bytes(range(32)) if serial==0 else '-'))
    return rows

def openings(inputs,outputs):
    if len(inputs)!=len(outputs):raise ValueError('component row mismatch')
    rows=[]
    for op in ('GCM','UDP'):
        index=next(i for i,line in enumerate(inputs) if line.startswith(op+' ') and len(line.split()[4 if op=='GCM' else 3])==34)
        parts=inputs[index].split();observed=outputs[index].split()
        if op=='GCM':
            good=['GCM_OPEN',parts[1],parts[2],parts[3],observed[2],observed[3]]
            slots=(1,2,3,4,5)
        else:
            good=['UDP_OPEN',parts[1],parts[2],observed[6],observed[7]]
            slots=(1,2,3,4)
        rows.append(' '.join(good))
        for slot in slots:
            changed=good.copy()
            if op=='UDP' and slot==2:changed[slot]=str(int(changed[slot])+1)
            elif changed[slot]=='-':changed[slot]='00'
            else:
                data=bytearray.fromhex(changed[slot]);data[0]^=1;changed[slot]=data.hex()
            rows.append(' '.join(changed))
    return rows

def summary(rows):return dict(sorted(Counter(row.split()[0] for row in rows).items()))
