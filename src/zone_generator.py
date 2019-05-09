import dns.resolver
import json

#All links were genrated using hacker link .com
f = open("Links/links.txt",'r')

urls = []
for link in f:
    #split http(s)
    newlink = link.split('//')
    #split (newline) at the end
    newlink = newlink[1].split('\n')
    #extract basic urls
    newlink = newlink[0].split('/')
    urls.append(newlink[0])

#Removing all duplicte links
urls = list(dict.fromkeys(urls))

for link in urls:
    a_list = []; c_list=[]
    try:
        a = dns.resolver.query(link,'A') 
        for answer in a:
            a_list.append({"name": "@", "ttl": 400, "value": answer.to_text() })
    except:
        pass
    try:
        cname = dns.resolver.query(link,'CNAME')    
        for answer in cname:
            c_list.append({ "name": "@", "ttl": 400, "value": answer.to_text() })
    except:
        pass
        data = {}
        if a_list == []:
            data = {"$origin":link+str('.'),"$ttl":3600,"cname":c_list}
        elif c_list == []:
            data = {"$origin":link+str('.'),"$ttl":3600,"a":a_list}
        else:
            data = {"$origin":link+str('.'),"$ttl":3600,"a":a_list,"cname":c_list}
        print(data)
        with open('zones/'+str(link)+'.zone','w+') as outfile:
            json.dump(data, outfile,indent=4)
    