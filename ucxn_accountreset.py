from lxml import etree
from lxml.etree import tostring
import requests
from getpass import getpass
import sys

def getcredentials():
    global ip,user,pwd,userid,pin
    #ip = raw_input('Enter the IP of your CUC Server. $')
    ip = '10.10.1.50'
    user = raw_input('Please enter your Admin ID. $')
    pwd = getpass('Please enter your Password. $')
    userid = raw_input('Enter the Users ID. $')
    pin = raw_input('Please enter PIN to Use. $')
    status = get_userquery()
    if status == 401:
        user = raw_input('Please enter your Admin ID. $')
        pwd = getpass('Please enter your Password. $')
        status = get_userquery()
    if status == 500:
        userid = raw_input('Enter the Users Ext. $')
        status = get_userquery()
    while True:
        userid = raw_input('Enter the Users Ext. To quit enter q. >')
        if userid is 'q':
            break
        status = get_userquery()

def get_userquery():
    url = 'https://%s/vmrest/users?query=(alias is %s)' % (ip, userid)
    r1 = requests.get(url,verify=False,auth=(user,pwd))
    if r1.status_code == 401:
        print 'Bad Username or Password. Please Reenter.'
        return r1.status_code
    userdoc = etree.XML(r1.content)
    find = etree.XPath("//User[alias='%s']/URI" % userid)
    try:
        objid_uri = find(userdoc)[0].text
    except IndexError:
        print 'That User Doesn\'t Exist. Please Try Again.'
        return 500
    get_usercred(objid_uri)

def get_usercred(objid):
    url = 'https://%s%s/credential/pin' % (ip, objid)
    r1 = requests.get(url,verify=False,auth=(user,pwd))
    usercred_doc = etree.XML(r1.content)
    #Use this to force Caller to Enter New PIN after PIN Reset
    crdpol_objid = etree.XPath("//CredentialPolicyObjectId/text()")
    crdpol_objid = crdpol_objid(usercred_doc)[0]
    #Check to See if Account is Locked
    ishacked = etree.XPath("//Hacked/text()")
    ishacked = ishacked(usercred_doc)[0]
    headers = {'Content-type':'application/xml'}
    if ishacked is 'true':
        put_unlockacct(usercred_doc,url,headers)
    put_pin(url,headers)
    put_credchangenextlogin(url,headers,crdpol_objid)

def put_unlockacct(doc,url,headers):
    hackcount = etree.XPath("//HackCount/text()")
    hackcount = hackcount(doc)[0]
    print 'The user has %s failed login attempts.' % hackcount
    hack_doc = etree.Element('Credential')
    hack_e = etree.SubElement(hack_doc,'HackCount')
    hack_e.text = '0'
    time_e = etree.SubElement(hack_doc,'TimeHacked')
    time_e.text = ''
    hackstr = etree.tostring(hack_doc, pretty_print=True)
    print 'Unlocking the Account. Please Wait.'
    r1 = requests.put(url,headers=headers,data=hackstr,verify=False,auth=(user,pwd))
    if r1.status_code == 204:
        print 'The Account has been Unlocked Successfully.'
        print 'Now we need to Change the PIN.'
    else:
        print 'Something went wrong with your request.'
        sys.exit(1)

def put_pin(url,headers):
    print 'Now Changing the Users PIN.'
    cred_doc = etree.Element('Credential')
    cred_e = etree.SubElement(cred_doc,'Credentials')
    cred_e.text = pin
    credstr = etree.tostring(cred_doc, pretty_print=True)
    r1 = requests.put(url,headers=headers,data=credstr,verify=False,auth=(user,pwd))
    if r1.status_code == 204:
        print 'You have successfully changed the PIN.'

def put_credchangenextlogin(url,headers,obj):
    chngpass_doc = etree.Element('Credential')
    lock_e = etree.SubElement(chngpass_doc, 'Locked')
    lock_e.text = 'false'
    dexpr_e = etree.SubElement(chngpass_doc, 'DoesntExpire')
    dexpr_e.text = 'true'
    cred_chng_e = etree.SubElement(chngpass_doc, 'CredMustChange')
    cred_chng_e.text = 'true'
    cred_polobj_e = etree.SubElement(chngpass_doc,'CredentialPolicyObjectId')
    cred_polobj_e.text = obj
    chngpass_str = etree.tostring(chngpass_doc, pretty_print=True)
    r1 = requests.put(url,headers=headers,data=chngpass_str,verify=False,auth=(user,pwd))
    if r1.status_code == 204:
        print 'The User Must Change PIN at Next Successful Login Attempt'

def main():
    getcredentials()
    print 'Thank you for using me! I hope it saved you precious time.'

if __name__ == '__main__':
    main()