import os
import argparse

def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--dir", help="Directory of pcap files")
    args = argparser.parse_args()
    
    pcap_dir = args.dir
    files = os.listdir(pcap_dir)
    os.mkdir(pcap_dir+'_json')
    for file in files:
        json = file.replace('pcap','json')
        command = "tshark -r ./"+pcap_dir+"/{} -Y 'ngap' -V -T json > ./".format(file)+pcap_dir+"_json/{}".format(json)
        os.popen(command)
        
if __name__ == '__main__':
    main()