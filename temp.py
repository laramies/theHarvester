class Creds():
    def __init__(self, id):
        self.id = id

    def get_key(self):
        with open('credentials.txt', 'r', encoding='UTF-8') as file:
            for line in file:
                line = line.strip().split(':')
                id = line[0]
                key = line[1]
                print('id: ', id)
                print('key: ', key)
                if 'hunter' in id:
                    return key
                elif 'bing' in id:
                    return key
                elif 'shodan' in id:
                    return key
                elif 'securityTrails' in id:
                    return key
                elif 'googleCSEapi' in id:
                    return key
                elif 'googleCSEid' in id:
                    return key
                else:
                    continue
        return None


x = 'YXNkYWRhZGFkYWQ='
import base64
print(base64.b64decode(x).decode('UTF-8'))