biwsbj1rb21hX3Rlc3Qscj1oeWRyYQ==
  n,,n=koma_test,r=hydra
cj1oeWRyYUZlM0Exc2NMN0MwanRLc20ra2NnOTZNV2c3NjlGdVJ1LHM9a002bFRqam5aVzRGOFdMYm95YWdjQT09LGk9NDA5Ng==
  r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,s=kM6lTjjnZW4F8WLboyagcA==,i=4096
dj1ZUWxlZ3ZiRXdEbzJvNjBZaUsyaUFrWXlQS0U9
  v=YQlegvbEwDo2o60YiK2iAkYyPKE=

clientFinalMessageBare = "c=biws,r=" .. serverNonce
saltedPassword = PBKDF2-SHA-1(normalizedPassword, salt, i)
clientKey = HMAC-SHA-1(saltedPassword, "Client Key")
storedKey = SHA-1(clientKey)
authMessage = initialMessage .. "," .. serverFirstMessage .. "," .. clientFinalMessageBare
clientSignature = HMAC-SHA-1(storedKey, authMessage)
clientProof = clientKey XOR clientSignature
serverKey = HMAC-SHA-1(saltedPassword, "Server Key")
serverSignature = HMAC-SHA-1(serverKey, authMessage)
clientFinalMessage = clientFinalMessageBare .. ",p=" .. base64(clientProof)

import base64
import hashlib
import hmac
import itertools

charset = "_abcdefghijklmnopqrstuvwxyz"

initial_message = "n=koma_test,r=hydra"
server_first_message = "r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,s=kM6lTjjnZW4F8WLboyagcA==,i=4096"
server_final_message_compare = "v=YQlegvbEwDo2o60YiK2iAkYyPKE="
r = server_first_message[2:server_first_message.find('s=')-1]
s = server_first_message[server_first_message.find('s=')+2:server_first_message.find('i=')-1]
i = server_first_message[server_first_message.find('i=')+2:]

for passlen in range(1,3):
    print ("test passlen %d" % passlen)
    for k in itertools.permutations(charset, passlen):
        password = "koma" + "".join(k)
        salt = base64.b64decode(s)
        client_final_message_bare = 'c=biws,r=' + r
        salt_password = hashlib.pbkdf2_hmac('sha1', password, salt, int(i))
        auth_message = initial_message + ',' + server_first_message + ',' + client_final_message_bare
        server_key = hmac.new(salt_password, 'Server Key', hashlib.sha1).digest()
        server_signature = hmac.new(server_key, auth_message, hashlib.sha1).digest()
        server_final_message = 'v=' + base64.b64encode(server_signature)
        if server_final_message == server_final_message_compare:
            print ("found the result")
            print (password)
            h = hashlib.new('sha1')
            h.update(password)
            print (h.hexdigest())
            exit(-1)
