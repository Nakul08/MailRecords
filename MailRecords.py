#################################
#   Authored By :               #
#                Nakul Ratti    #
#################################
import dns.resolver
import re
import csv
import argparse

result={"MX":[],"DMARC":"","DKIM":"","SPF":""}

dkim_sw=1

def mx(domain):
    global dkim_sw
    dkim_sw=1
    l=[]
    d = domain
    try:
        answers = dns.resolver.resolve(d,'MX')
        print("[-] MX Record :",end=" ")
        for i in answers:
            tmp=str(i)
            tmp = tmp.split(" ")[1]
            print('"{0}"'.format(tmp[:-1]),end=" ")
            l.append(tmp)
            result["MX"]=l
        print()
    except:
        print("[!] MX Server does not exist")
        result["MX"]="None"
        dkim_sw=0
def dmarc(domain):
    d = domain
    pat=re.compile(r'^\"v=DMARC\w*')
    try:
        answers = dns.resolver.resolve("_dmarc."+d,'TXT')
        for i in answers:
            if(len(pat.findall(str(i)))>=1):
                print("[-] DMARC Record :",end=" ")
                print(str(i))
                result["DMARC"]=str(i)
    except:
        print("\n[!] DMARC Record Not Implemented!")
        result["DMARC"]="None"

def dkim(domain):
    if(dkim_sw==1):
        d=domain
        #Selector list taken from online github scripts
        s=["selector1","selector2","mailgun","dkim","default","google","zix","google","k1","mxvault","everlytickey1", 'mail', 'class', 'smtpapi', 'dkim', 'bfi', 'spop', 'spop1024', 'beta', 'domk', 'dk', 'ei', 'smtpout', 'sm', 'authsmtp', 'alpha', 'mesmtp', 'cm', 'prod', 'pm', 'gamma', 'dkrnt', 'dkimrnt', 'private', 'gmmailerd', 'pmta', 'x', 'selector', 'qcdkim', 'postfix', 'mikd', 'main', 'm', 'dk20050327', 'delta', 'yibm', 'wesmail', 'test', 'stigmate', 'squaremail', 'sitemail', 'sasl', 'sailthru', 'responsys', 'publickey', 'proddkim', 'mail-in', 'key', 'ED-DKIM', 'ebmailerd', 'Corporate', 'care', '0xdeadbeef', 'yousendit', 'www', 'tilprivate', 'testdk', 'snowcrash', 'smtpcomcustomers', 'smtpauth', 'smtp', 'sl', 'sharedpool', 'ses', 'server', 'scooby', 'scarlet', 'safe', 's', 'pvt', 'primus', 'primary', 'postfix.private', 'outbound', 'originating', 'one', 'neomailout', 'mx', 'msa', 'monkey', 'mkt', 'mimi', 'mdaemon', 'mailrelay', 'mailjet', 'mail-dkim', 'mailo', 'mandrill', 'lists', 'iweb', 'iport', 'id', 'hubris', 'googleapps', 'global', 'gears', 'exim4u', 'exim', 'et', 'dyn', 'duh', 'dksel', 'dkimmail', 'corp', 'centralsmtp', 'ca', 'bfi', 'auth', 'allselector', 'zendesk1']
        ans=1
        i=0
        while ans<=1 and i<=len(s):
            try:
                answers=dns.resolver.resolve(s[i]+"._domainkey."+d,"TXT")
                for data in answers:
                    print("\n\n[-] DKIM Signature Verified using selector "+ s[i])
                    print("[-] DKIM Value: ",end=" ")
                    print(str(data))
                    result["DKIM"]=str(data)
                    ans=2
                    i=i+1
            except:
                i=i+1
                #print("Failed DKIM for selector : "+s[i])
        if(ans==1):
            print("\n[!] Cannot verify DKIM Record using available selectors")
            result["DKIM"]="Unverified"
    else:
        result["DKIM"]="Not Required"
        print("\n[-] DKIM not required!!")


def spf(domain):
    d = domain
    pat=re.compile(r'^\"v=spf1\w*')
    try:
        answers = dns.resolver.resolve(d,'TXT')
        print("\n[-] SPF Record :",end=" ")
        for i in answers:
            if(len(pat.findall(str(i)))>=1):
                print(str(i),end=" ")
                result["SPF"]=str(i)
        print()
    except:
        print("[!] No SPF policy exists")
        result["SPF"]="None"
        
       
def write_file(test_domain):
    global file_name
    f=open(file_name,"a",newline='')
    wr=csv.writer(f)
    wr.writerow([test_domain,result["MX"],result["SPF"],result["DKIM"],result["DMARC"]])
    f.close()


def allcheck(d,f):
    print("\n\n[-] Domain: "+d)
    mx(d)
    dmarc(d)
    spf(d)
    dkim(d)
    print("")
    print("-"*120)
    if(f==1):
        write_file(d)
    
def mk_file():
    global file_name
    f=open(file_name,"w",newline='')
    wr=csv.writer(f)
    wr.writerow(["Domain","MX","SPF","DKIM","DMARC"])
    f.close()

if __name__ == "__main__":
    print()
    parser=argparse.ArgumentParser(description="Program to check for MX | SPF | DMARC and DKIM records")
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d",help="Single domain value(domain.tld)")
    group.add_argument("-D",help="Line separated domain file")
    parser.add_argument("-o",help="Output file",required=False)
    args=parser.parse_args()
    global file_name
    file_name=args.o
    if(args.D != None):
        f=open(args.D,"r") #path to Domain.txt File
        domains=f.read().splitlines()
        if(args.o!=None):
            mk_file()
            for i in domains:
                allcheck(i,1)
            print("\n\n[-] File written successfully!!\n")
        else:
            for i in domains:
                allcheck(i,0)
    else:
        if(args.o!=None):
            mk_file()
            allcheck(args.d,1)
            print("\n\n[-] File written successfully!!\n")
        else:
            allcheck(args.d,0)