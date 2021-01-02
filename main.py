import os
import re
from csv import DictWriter
from json import load

from ipinfo import getHandler


def load_ips():
    with open("src/shopsv2.json", "r", encoding="utf8") as src_ip_file:
        ip_list = load(fp=src_ip_file)
    return ip_list


def whois_isp(ip_addr, token):

    handler = getHandler(access_token=token)
    details = handler.getDetails(ip_addr)
    return details


def write_to_file(string, header):
    ready_to_write = string
    if header is False:
        with open("ISP and IP.csv", "a", newline="") as csvfile:
            fieldnames = ['Number shop', 'ISP first - ip / ISP second - ip', 'Legal address']
            writer = DictWriter(f=csvfile, fieldnames=fieldnames)
            writer.writerow(ready_to_write)
    else:
        with open("ISP and IP.csv", "w", newline="") as csvfile:
            fieldnames = ['Number shop', 'ISP first - ip / ISP second - ip', 'Legal address']
            writer = DictWriter(f=csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(ready_to_write)


def prepare_to_csv(chunk):

    for number_shop in sorted(chunk):
        isp_info = ''

        for key in chunk[number_shop].keys():
            if isp_info != '':
                isp_info += ' /\n '
            if key in ["IP1", "IP2"]:
                isp_info += chunk[number_shop][key]

        ready_to_write = {'Number shop': chunk[number_shop]['shop'],
                          'ISP first - ip / ISP second - ip': isp_info,
                          'Legal address': 'Fill yourself'}

        if os.path.exists("ISP and IP.csv") is True:
            write_to_file(string=ready_to_write, header=False)
        else:
            write_to_file(string=ready_to_write, header=True)


if __name__ == '__main__':

    """
    ip_dict - содержит json список, внутри которого лежит словарь с 2 или 3 мя ключами, 
    в зависимости от количества IP адресов на магазине.
    
    new_ip_dict - содержит преобразованный список ip_dict к виду:
    key - номер магазина: value - словарь по номеру магазина добавленными к ключами IP адресов названиями провайдеров.
    """

    ip_dict = load_ips()
    new_ip_dict = dict()
    for item in ip_dict:
        new_ip_dict[int(item.get("shop"))] = item

    with open("config.json") as config:
        cfg = load(config)

    for j in sorted(new_ip_dict):
        for k in new_ip_dict[j].keys():
            if k in ["IP1", "IP2"]:
                detail = whois_isp(ip_addr=new_ip_dict[j][k], token=cfg["token"])
                new_ip_dict[j][k] = f"{re.sub('AS.{1,6}', '', detail.org)} - {detail.ip}"

    prepare_to_csv(new_ip_dict)
