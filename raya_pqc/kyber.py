import os, hashlib
Q,N,K=3329,256,2; ETA1,ETA2,DU,DV=3,2,10,4
F_INV=pow(128,-1,Q); SK_SZ=K*N*12//8; PK_SZ=K*N*12//8+32
def _br7(n):
    r=0
    for _ in range(7): r=(r<<1)|(n&1); n>>=1
    return r
ZETAS=[pow(17,_br7(i),Q) for i in range(128)]
def ntt(f):
    f=list(f); k=1; l=128
    while l>=2:
        for s in range(0,N,2*l):
            z=ZETAS[k]; k+=1
            for j in range(s,s+l):
                t=z*f[j+l]%Q; f[j+l]=(f[j]-t)%Q; f[j]=(f[j]+t)%Q
        l>>=1
    return f
def intt(f):
    f=list(f); k=127; l=2
    while l<=128:
        for s in range(0,N,2*l):
            z=ZETAS[k]; k-=1
            for j in range(s,s+l):
                t=f[j]; f[j]=(t+f[j+l])%Q; f[j+l]=z*(f[j+l]-t)%Q
        l<<=1
    return [x*F_INV%Q for x in f]
def pmul(a,b):
    r=[0]*N
    for i in range(64):
        z=ZETAS[64+i]; nz=(Q-z)%Q
        r[4*i]=(a[4*i]*b[4*i]+a[4*i+1]*b[4*i+1]*z)%Q
        r[4*i+1]=(a[4*i]*b[4*i+1]+a[4*i+1]*b[4*i])%Q
        r[4*i+2]=(a[4*i+2]*b[4*i+2]+a[4*i+3]*b[4*i+3]*nz)%Q
        r[4*i+3]=(a[4*i+2]*b[4*i+3]+a[4*i+3]*b[4*i+2])%Q
    return r
def padd(a,b): return [(x+y)%Q for x,y in zip(a,b)]
def psub(a,b): return [(x-y)%Q for x,y in zip(a,b)]
def H(d): return hashlib.sha3_256(d).digest()
def G(d): h=hashlib.sha3_512(d).digest(); return h[:32],h[32:]
def PRF(s,b,n): sh=hashlib.shake_256(); sh.update(s+bytes([b])); return sh.digest(n)
def XOF(seed,i,j,n): sh=hashlib.shake_128(); sh.update(seed+bytes([i,j])); return sh.digest(n)
def sample_ntt(seed,i,j):
    buf=XOF(seed,i,j,672); a=[]; idx=0
    while len(a)<N and idx+2<len(buf):
        d1=buf[idx]+256*(buf[idx+1]&0xF); d2=(buf[idx+1]>>4)+16*buf[idx+2]
        if d1<Q: a.append(d1)
        if d2<Q and len(a)<N: a.append(d2)
        idx+=3
    while len(a)<N: a.append(0)
    return a[:N]
def cbd(eta,b):
    f=[0]*N
    for i in range(N):
        av=bv=0
        for j in range(eta):
            p=2*i*eta+j; av+=(b[p>>3]>>(p&7))&1
            p=2*i*eta+eta+j; bv+=(b[p>>3]>>(p&7))&1
        f[i]=(av-bv)%Q
    return f
def enc_poly(f,d):
    bits=[]
    for c in f: bits.extend((c>>i)&1 for i in range(d))
    out=bytearray(len(bits)//8)
    for i,b in enumerate(bits): out[i//8]|=b<<(i%8)
    return bytes(out)
def dec_poly(b,d):
    f=[0]*N
    for i in range(N):
        for j in range(d):
            p=i*d+j; f[i]|=((b[p>>3]>>(p&7))&1)<<j
    return f
def cmp(x,d): return round(x*(1<<d)/Q)%(1<<d)
def dcmp(x,d): return round(x*Q/(1<<d))
def enc_vec(v,d): return b''.join(enc_poly(p,d) for p in v)
def dec_vec(b,d):
    sz=N*d//8; return [dec_poly(b[i*sz:(i+1)*sz],d) for i in range(K)]
def pke_keygen():
    d=os.urandom(32); rho,sigma=G(d)
    A=[[ntt(sample_ntt(rho,i,j)) for j in range(K)] for i in range(K)]
    sv=[ntt(cbd(ETA1,PRF(sigma,i,64*ETA1))) for i in range(K)]
    ev=[cbd(ETA1,PRF(sigma,K+i,64*ETA1)) for i in range(K)]
    t=[]
    for i in range(K):
        acc=[0]*N
        for j in range(K): acc=padd(acc,pmul(A[i][j],sv[j]))
        t.append(padd(acc,ntt(ev[i])))
    return enc_vec(t,12)+rho, enc_vec(sv,12)
def pke_enc(pk,msg32,coins):
    t=dec_vec(pk[:K*N*12//8],12); rho=pk[K*N*12//8:]
    AT=[[ntt(sample_ntt(rho,j,i)) for j in range(K)] for i in range(K)]
    rv=[ntt(cbd(ETA1,PRF(coins,i,64*ETA1))) for i in range(K)]
    e1=[cbd(ETA2,PRF(coins,K+i,64*ETA2)) for i in range(K)]
    e2=cbd(ETA2,PRF(coins,2*K,64*ETA2))
    u=[]
    for i in range(K):
        acc=[0]*N
        for j in range(K): acc=padd(acc,pmul(AT[i][j],rv[j]))
        u.append(padd(intt(acc),e1[i]))
    vt=[0]*N
    for i in range(K): vt=padd(vt,pmul(t[i],rv[i]))
    vt=intt(vt)
    mp=[((msg32[i//8]>>(i%8))&1)*(Q//2) for i in range(N)]
    v=padd(padd(vt,e2),mp)
    c1=b''.join(enc_poly([cmp(c,DU) for c in p],DU) for p in u)
    c2=enc_poly([cmp(c,DV) for c in v],DV)
    return c1+c2
def pke_dec(sk_bytes,ct):
    sv=dec_vec(sk_bytes,12); sz=K*N*DU//8
    u=[[dcmp(c,DU) for c in dec_poly(ct[i*N*DU//8:(i+1)*N*DU//8],DU)] for i in range(K)]
    v=[dcmp(c,DV) for c in dec_poly(ct[sz:],DV)]
    su=[0]*N
    for i in range(K): su=padd(su,pmul(sv[i],ntt(u[i])))
    w=psub(v,intt(su)); msg=bytearray(32)
    for i in range(N): msg[i//8]|=(round(w[i]*2/Q)%2)<<(i%8)
    return bytes(msg)
def keygen():
    pk,sk_pke=pke_keygen(); z=os.urandom(32); h=H(pk)
    return pk, sk_pke+pk+h+z
def encaps(pk):
    m=os.urandom(32); m2,_=G(m+H(pk)); Kbar,r=G(m2+H(pk))
    ct=pke_enc(pk,m2,r)
    return ct, hashlib.shake_256(Kbar+H(ct)).digest(32)
def decaps(sk,ct):
    sk_pke=sk[:SK_SZ]; pk_=sk[SK_SZ:SK_SZ+PK_SZ]
    h=sk[SK_SZ+PK_SZ:SK_SZ+PK_SZ+32]; z=sk[-32:]
    m2=pke_dec(sk_pke,ct); Kbar,r=G(m2+h); ct2=pke_enc(pk_,m2,r)
    src=Kbar if ct==ct2 else z
    return hashlib.shake_256(src+H(ct)).digest(32)
