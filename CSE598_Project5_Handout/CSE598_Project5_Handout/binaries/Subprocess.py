import subprocess
import re

input_vari1 = ["1","1","1","1","2","2","3","3","4","4","4","4","4"]
input_vari2 = ["2","2","2","2","3","3","4","5","5","5","5","6","7"]
input_vari3 = ["3","4","5","6","4","5","5","6","6","7","8","8","8"]

for i in range(11):
    result_rec = subprocess.Popen(['./openFHE_BFV',input_vari1[i],input_vari2[i],input_vari3[i]])## input_vari[i] ,stdout=subprocess.PIPE
    result_rec.wait()
    '''
    text = result_rec.stdout.read().decode()
    
    match = re.search(r"Mult time #1 \* #2 \* #3:\s(\d)", text)
    if match:
        print("resuslt_mul is,",match.group(1))
    else:
        print("result not found")
    
    match1 = re.search(r"Add time #1 + #2 + #3:\s(\d)", text)
    print("resuslt_add is,",match1.group(1))
    '''

