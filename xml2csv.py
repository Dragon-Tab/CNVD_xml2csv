from bs4 import BeautifulSoup
import csv
import os
'''
遍历所有xml文件到csv
'''
#xml文件绝对路径
url = r"C:\\xxx\\xxx\\xxx\\xxx\\xxx\\cnvd共享漏洞库xml文件\\"
files = os.listdir(url)

#写表头
with open('cnvd.csv', 'w', newline='', encoding='utf-8-sig') as f1_output:
    csv1_output = csv.writer(f1_output)
    csv1_output.writerow(['CNVD-ID', '漏洞名称', '公开日期', '危害级别', '影响产品', 'CVE-ID', '漏洞描述', '漏洞类型', '参考链接', '漏洞解决方案', '厂商补丁', '报送时间', '补丁说明']) 
#遍历文件名
for file in files:
    f = os.path.join(url, file)

    soup = BeautifulSoup(open(f, encoding='utf-8'))
    with open('cnvd.csv', 'a+', newline='', encoding='utf-8-sig') as f_output:
        csv_output = csv.writer(f_output)
        #查找vulnerability节点
        for tns in soup.find_all("vulnerability"):
            list = []
            prod = ''
            #遍历除影响产品外其他数据
            for entry in (['number', 'title', 'opentime', 'serverity', 'cvenumber', 'description', 'isevent', 'referencelink', 'formalway', 'patchname', 'submittime', 'patchdescription']):
                if tns.find(entry):
                    value = tns.find(entry).text
                else:
                    value = 'null'
                list.append(value)
            #遍历影响产品，拼接字符串，将影响产品数据插入list[4]
            for product in tns.find_all("product"):
                prod = prod+product.text+"\n"
            
            list.insert(4,prod)
            #writerow必须是列表
            csv_output.writerow(list)

