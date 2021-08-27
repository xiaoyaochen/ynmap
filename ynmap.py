import argparse,codecs
import pandas as pd
import nmap
from datetime import datetime

class yNmap:
    def __init__(self,hosts,ports,nmap_arg) -> None:
        self.nmap_arg = nmap_arg
        self.hosts = hosts
        self.posts = ports
        self.nm = nmap.PortScanner()
        self.result = []

    def nmscan(self):
        self.nm.scan(hosts=self.hosts,ports=self.posts,arguments=self.nmap_arg)
        self.parse_nmap(self.nm._scan_result)
        

    def parse_nmap(self,scan_result):
        for k,v in scan_result['scan'].items():
            for name,portinfo in v.items():
                if name == 'tcp':
                    for port,info in portinfo.items():
                        if port == 80:
                            url = 'http://'+k
                        elif port == 443:
                            url = 'https://'+k
                        else:
                            if 'https' in info['name']:
                                url = f'https://{k}:{port}'
                            elif 'http' in info['name']:
                                url = f'http://{k}:{port}'
                            else:
                                url = ''
                        _ = {'ip':k,'port':port,'state':info['state'],'protocol':info['name'],
                             'product':info['product'],'url':url,'version':info['version'],'extrainfo':info['extrainfo']}
                        _.update(self.parse_http(info))
                        self.result.append(_)
    def export_xlsx(self,excelname):
        pd_xlsx = pd.DataFrame.from_dict(self.result)
        pd_xlsx.to_excel(excelname,index=False,engine='xlsxwriter')

    def parse_http(self,info):
        parse_info = {}
        if 'script' in info:
            if 'http-info' in info['script']:
                try:
                    parse_info['title'],parse_info['status'],parse_info['server'] = info['script']['http-info'].split('\n')
                except:
                    parse_info['title'] = info['script']['http-info']
                try:
                    parse_info['title'] = codecs.escape_decode(parse_info['title'].replace("\\\\","\\"), 'hex-escape')[0].decode()
                except Exception as e:
                    print(e)
                del info['script']['http-info']
            parse_info['script'] = info['script']
        return parse_info

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file',dest='File',type=str,help='IP文件')
    parser.add_argument('-i','--ips',dest='Ips',type=str,help='IP')
    parser.add_argument('-p','--ports',dest='Ports',type=str,help='端口')
    parser.add_argument('-s','--scanarg',dest='Scanarg',type=str,
                        default='-sS -sV -Pn -n --min-hostgroup 1024 --min-parallelism 100 --min-rate=10000 -T4 --script=http-info',
                        help='nmap扫描参数')
    parser.add_argument('-b','--brutearg',dest='Brutearg',type=str,help='nmap爆破脚本')
    parser.add_argument('-v','--vularg',dest='Vularg',type=str,help='nmap漏洞脚本')
    args  = parser.parse_args()
    Ips = args.Ips
    Scanarg = args.Scanarg if not args.Brutearg else args.Scanarg+',brute'
    Scanarg = Scanarg if not args.Vularg else Scanarg+',vuln'

    if args.File:
        with open(args.File,'r',encoding='utf-8') as r:
            Ips = r.readline().strip()
    File = f' -iL {args.File}' if args.File else ''
    Ports = args.Ports
    excelname = './output/端口扫描{}.xlsx'.format(datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
    start_time = datetime.now()
    nmap_arg = f'{Scanarg}{File}'
    print(nmap_arg)
    ##开始扫描
    ynmap = yNmap(Ips,Ports,nmap_arg)
    ynmap.nmscan()
    ynmap.export_xlsx(excelname)
    end_time = datetime.now() - start_time
    print("扫描消耗时间：{}分钟".format(end_time.seconds//60))