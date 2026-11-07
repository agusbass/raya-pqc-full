"""Pure-Python ML-DSA-44 reference implementation (NIST FIPS 204).

WARNING: This module is a REFERENCE IMPLEMENTATION ONLY.
  - NOT constant-time — vulnerable to timing side-channel attacks.
  - NOT for production. Install liboqs: pip install liboqs
  - Implements ML-DSA-44 (k=4, l=4), NOT the ML-DSA-65 used by the main API.

Used internally only when RAYA_ALLOW_FALLBACK=1 (dev/test).
"""
import os,hashlib
Q=8380417;N=256;K=4;L=4;ETA=2;TAU=39;BETA=TAU*ETA;GAMMA1=1<<17;GAMMA2=(Q-1)//88;OMEGA=80;D=13
def _br8(n):
    r=0
    for _ in range(8): r=(r<<1)|(n&1); n>>=1
    return r
ZETAS=[0]+[pow(1753,_br8(k),Q) for k in range(1,256)];FINV=pow(256,-1,Q)
def ntt(f):
    a=list(f);k=0;l=128
    while l>0:
        for s in range(0,N,2*l):
            k+=1;z=ZETAS[k]
            for j in range(s,s+l):
                t=z*a[j+l]%Q;a[j+l]=(a[j]-t)%Q;a[j]=(a[j]+t)%Q
        l>>=1
    return a
def intt(f):
    a=list(f);k=256;l=1
    while l<=128:
        for s in range(0,N,2*l):
            k-=1;z=ZETAS[k]
            for j in range(s,s+l):
                t=a[j];a[j]=(t+a[j+l])%Q;a[j+l]=z*(a[j+l]-t)%Q
        l<<=1
    return [x*FINV%Q for x in a]
def pmul(a,b): return [a[i]*b[i]%Q for i in range(N)]
def padd(a,b): return [(x+y)%Q for x,y in zip(a,b)]
def psub(a,b): return [(x-y)%Q for x,y in zip(a,b)]
def inf_norm(f): return max(abs(x if x<=Q//2 else x-Q) for x in f)
def vec_norm(v): return max(inf_norm(p) for p in v)
def cmod(a,m): r=a%m; return r-m if r>m//2 else r
def decompose(r):
    r%=Q;r0=cmod(r,2*GAMMA2)
    if r-r0==Q-1: return 0,r0-1
    return (r-r0)//(2*GAMMA2),r0
def highbits(r): return decompose(r)[0]
def lowbits(r): return decompose(r)[1]
def power2round(r):
    r%=Q;r0=cmod(r,1<<D);return (r-r0)>>D,r0
def makehint(z,r): return 0 if highbits(r)==highbits((r+z)%Q) else 1
def usehint(h,r):
    m=(Q-1)//(2*GAMMA2);r1,r0=decompose(r)
    if h: return (r1+(1 if r0>0 else -1))%m
    return r1
def vec_p2r(v):
    hi,lo=[],[]
    for p in v:
        h,l=[],[]
        for x in p: a,b=power2round(x);h.append(a);l.append(b)
        hi.append(h);lo.append(l)
    return hi,lo
def vec_hb(v): return [[highbits(x) for x in p] for p in v]
def make_hint_vec(nct0,wcs2ct0):
    return [[makehint(nct0[i][j],wcs2ct0[i][j]) for j in range(N)] for i in range(K)]
def use_hint_vec(h,r):
    return [[usehint(h[i][j],r[i][j]) for j in range(N)] for i in range(K)]
def H(d,n): sh=hashlib.shake_256();sh.update(d);return sh.digest(n)
def XOF128(s,i,j,n): sh=hashlib.shake_128();sh.update(s+bytes([i,j]));return sh.digest(n)
def expand_A(rho):
    A=[]
    for i in range(K):
        row=[]
        for j in range(L):
            buf=XOF128(rho,i,j,672);a=[];idx=0
            while len(a)<N and idx+2<len(buf):
                d1=buf[idx]+256*(buf[idx+1]&0xF);d2=(buf[idx+1]>>4)+16*buf[idx+2]
                if d1<Q: a.append(d1)
                if d2<Q and len(a)<N: a.append(d2)
                idx+=3
            while len(a)<N: a.append(0)
            row.append(a[:N])
        A.append(row)
    return A
def sample_eta(seed,nonce):
    sh=hashlib.shake_256();sh.update(seed+nonce.to_bytes(2,'little'))
    buf=sh.digest(N*2*ETA//8);f=[0]*N
    for i in range(N):
        av=bv=0
        for j in range(ETA):
            p=2*i*ETA+j;av+=(buf[p>>3]>>(p&7))&1
            p=2*i*ETA+ETA+j;bv+=(buf[p>>3]>>(p&7))&1
        f[i]=(av-bv)%Q
    return f
def expand_mask(rho_p,kappa):
    y=[]
    for i in range(L):
        sh=hashlib.shake_256();sh.update(rho_p+(kappa+i).to_bytes(2,'little'))
        buf=sh.digest(576);f=[0]*N
        for j in range(N):
            s=18*j;val=0
            for b in range(18): pos=s+b;val|=((buf[pos>>3]>>(pos&7))&1)<<b
            f[j]=(GAMMA1-val)%Q
        y.append(f)
    return y
def sample_ball(seed):
    buf=H(seed,200);signs=int.from_bytes(buf[:8],'little')
    c=[0]*N;s=0;idx=8
    for i in range(N-TAU,N):
        j=256
        while j>i:
            j=buf[idx]%256;idx+=1
            if idx>=len(buf): buf+=H(seed+bytes([idx]),128)
        c[i]=c[j];c[j]=(Q-1) if (signs>>s)&1 else 1;s+=1
    return c
def mat_vec(A,v):
    res=[]
    for row in A:
        acc=[0]*N
        for j in range(L): acc=padd(acc,pmul(row[j],v[j]))
        res.append(acc)
    return res
def encode_w1(w1):
    bits=[]
    for p in w1:
        for x in p: bits.extend((x>>i)&1 for i in range(6))
    out=bytearray(len(bits)//8)
    for i,b in enumerate(bits): out[i//8]|=b<<(i%8)
    return bytes(out)
def _pack(arr,bw):
    out=bytearray();buf=0;bl=0
    for x in arr:
        buf|=(int(x)&((1<<bw)-1))<<bl;bl+=bw
        while bl>=8: out.append(buf&0xFF);buf>>=8;bl-=8
    if bl: out.append(buf)
    return bytes(out)
def _unpack(data,n,bw):
    arr=[];buf=0;bl=0;idx=0
    for _ in range(n):
        while bl<bw and idx<len(data): buf|=data[idx]<<bl;bl+=8;idx+=1
        arr.append(buf&((1<<bw)-1));buf>>=bw;bl-=bw
    return arr
def _enc_t1(t1): return b''.join(_pack(p,10) for p in t1)
def _dec_t1(b): return [_unpack(b[i*320:(i+1)*320],N,10) for i in range(K)]
def _enc_s(s): return b''.join(_pack([(ETA-x)%Q for x in p],4) for p in s)
def _dec_s(b,count):
    sz=N*4//8
    return [[(ETA-x)%Q for x in _unpack(b[i*sz:(i+1)*sz],N,4)] for i in range(count)]
def _enc_t0(t0):
    out=[]
    for p in t0:
        enc=[(1<<(D-1))-(x if x<=Q//2 else x-Q) for x in p]
        out.append(_pack(enc,D))
    return b''.join(out)
def _dec_t0(b):
    sz=D*N//8;res=[]
    for i in range(K):
        vals=_unpack(b[i*sz:(i+1)*sz],N,D)
        res.append([((1<<(D-1))-v)%Q for v in vals])
    return res
def _enc_z(z):
    out=[]
    for p in z:
        vals=[(GAMMA1-(x if x<=Q//2 else x-Q))%(2*GAMMA1) for x in p]
        out.append(_pack(vals,18))
    return b''.join(out)
def _dec_z(b):
    sz=18*N//8;res=[]
    for i in range(L):
        vals=_unpack(b[i*sz:(i+1)*sz],N,18)
        res.append([(GAMMA1-v)%Q for v in vals])
    return res
def keygen():
    xi=os.urandom(32);seeds=H(xi,128)
    rho=seeds[:32];rho_p=seeds[32:96];K_=seeds[96:]
    A=expand_A(rho)
    s1=[sample_eta(rho_p,i) for i in range(L)]
    s2=[sample_eta(rho_p,L+i) for i in range(K)]
    s1h=[ntt(x) for x in s1]
    As1=[intt(a) for a in mat_vec(A,s1h)]
    t=[padd(As1[i],s2[i]) for i in range(K)]
    t1,t0=vec_p2r(t);t1b=_enc_t1(t1)
    pk=rho+t1b;tr=H(pk,64)
    sk=rho+K_+tr+_enc_s(s1)+_enc_s(s2)+_enc_t0(t0)
    return pk,sk
def sign(sk,msg):
    rho=sk[:32];K_=sk[32:64];tr=sk[64:128];off=128
    s_sz=N*4//8
    s1=_dec_s(sk[off:off+L*s_sz],L);off+=L*s_sz
    s2=_dec_s(sk[off:off+K*s_sz],K);off+=K*s_sz
    t0=_dec_t0(sk[off:])
    A=expand_A(rho)
    s1h=[ntt(x) for x in s1];s2h=[ntt(x) for x in s2];t0h=[ntt(x) for x in t0]
    mu=H(tr+msg,64);rnd=os.urandom(32);rho_p=H(K_+rnd+mu,64)
    kappa=0
    while True:
        y=expand_mask(rho_p,kappa);kappa+=L
        yh=[ntt(p) for p in y]
        w=[intt(a) for a in mat_vec(A,yh)]
        w1=vec_hb(w);c_tilde=H(mu+encode_w1(w1),32)
        c=sample_ball(c_tilde);ch=ntt(c)
        z=[padd(y[i],intt(pmul(ch,s1h[i]))) for i in range(L)]
        if vec_norm(z)>=GAMMA1-BETA: continue
        Cs2=[intt(pmul(ch,s2h[i])) for i in range(K)]
        w_cs2=[psub(w[i],Cs2[i]) for i in range(K)]
        r0=[[lowbits(x) for x in p] for p in w_cs2]
        if max(inf_norm(p) for p in r0)>=GAMMA2-BETA: continue
        Ct0=[intt(pmul(ch,t0h[i])) for i in range(K)]
        nct0=[[(Q-x)%Q for x in Ct0[i]] for i in range(K)]
        wcs2ct0=[padd(w_cs2[i],Ct0[i]) for i in range(K)]
        h=make_hint_vec(nct0,wcs2ct0)
        if sum(sum(row) for row in h)>OMEGA: continue
        return c_tilde+_enc_z(z)+b''.join(bytes(row) for row in h)
def verify(pk,msg,sig):
    rho=pk[:32];t1=_dec_t1(pk[32:])
    c_tilde=sig[:32];off=32
    sz=18*N//8;z=_dec_z(sig[off:off+L*sz]);off+=L*sz
    h=[[sig[off+i*N+j] for j in range(N)] for i in range(K)]
    if vec_norm(z)>=GAMMA1-BETA: return False
    if sum(sum(row) for row in h)>OMEGA: return False
    A=expand_A(rho);tr=H(pk,64);mu=H(tr+msg,64)
    c=sample_ball(c_tilde);ch=ntt(c)
    zh=[ntt(p) for p in z]
    Az=[intt(a) for a in mat_vec(A,zh)]
    ct1=[intt(pmul(ch,ntt([x<<D for x in p]))) for p in t1]
    w_p=[psub(Az[i],ct1[i]) for i in range(K)]
    w1_p=use_hint_vec(h,w_p)
    return c_tilde==H(mu+encode_w1(w1_p),32)
