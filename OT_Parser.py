import argparse
import os
import ipaddress

current_line = ""   #global variable containing the information of the line python is currently reading
output_cache = ''  #using single quotes because strings with double quotes will be concatenated into it.
computer_name = ""   #grabbing this from line 1 of txt file
dirs = ""

parser = argparse.ArgumentParser(description='ICS Script')
parser.add_argument('-f', "--files", default=[1], type=int, nargs=1,
                    help='number of machines that will be parsed', dest='file')
args = parser.parse_args()


def file_loop(num_of_files):
    global dirs, output_cache
    for x in range(num_of_files[0]):
        print("Machine Count: " + str(x + 1))
        computer = input("Please give the file path for the machine output: ")
        dirs = computer
        main(computer)
        output_cache += "\n"


def main(computer):
    global current_line, computer_name
    data = ""
    file = open(computer, "r")
    read_line(file)
    computer_name = current_line.split()[0]


    print("\n1. System Information \n")
    add_to_cache(computer_name)
    read_line(file)
    read_line(file)
    add_to_cache(current_line)
    read_line(file)
    add_to_cache(current_line)


    print("\n2. Ipconfig \n")
    while "Proto" not in current_line:
        read_line(file)
        if "IPv4" in current_line:
            current_line = current_line.split()[-1]
            data += current_line + "    "
        elif "Subnet" in current_line:
            current_line = current_line.split()[-1]
            data += current_line + "\n"
    add_to_cache(data)
    data = ""


    print("\n3. Netstat \n")
    external_port = []
    internal_port = []
    private_ip = []
    public_ip = []

    while True:
        read_line(file)
        if '\\' in current_line or '\n  ' == current_line:
            break
        parse = current_line
        parse = parse.strip()
        parse = parse.split()[1]
        if "0.0.0.0" in parse:
            external_port.append(current_line)
        elif "127.0.0.1" in parse:
            internal_port.append(current_line)
        elif "ESTABLISHED" in current_line and "[" not in current_line:
            local_address = current_line.strip().split()[1].split(':')[0]
            foreign_address = current_line.strip().split()[2].split(':')[0]
            print(local_address)
            if ipaddress.ip_address(local_address).is_global or ipaddress.ip_address(foreign_address).is_global:
                public_ip.append(current_line)
            else:
                private_ip.append(current_line)

    print("\n3a. Public IP Connections \n")
    for connection in public_ip:
        data += connection + "\n"
    add_to_cache(data)
    data = ""

    print("\n3b. Open insecure ports \n")
    for connection in external_port:
        local_port = connection.strip().split()[1].split(':')[1]
        foreign_port = connection.strip().split()[2].split(':')[1]
        #
        #Modify the string below for the external facing ports you are interested in finding
        #
        if local_port in "21,80,20,23,110,161,1433,1434,5800,5900":
            data += connection + "\n"
    add_to_cache(data)
    data = ""


    print("\n3c. Interesting Internal Facing Ports \n")
    lineselect(internal_port)


    print("\n3d. Established administrative sessions \n")
    for connection in private_ip:
        local_port = connection.strip().split()[1].split(':')[1]
        foreign_port = connection.strip().split()[2].split(':')[1]
        #
        # Modify the string below for connections to strange ports.
        # Note: the script can't filter by private/public connections.
        if local_port in "21,22,23,3389,1433,1434,5800,5900,110,161" or foreign_port in \
                "21,22,23,3389,1433,1434,5800,5900,110,161" and "ESTABLISHED" in connection.upper():
            data += connection + "\n"
    add_to_cache(data)
    data = ""
    read_line(file)


    print("\n3d. Active Routes \n")
    if current_line.split()[0] == "0.0.0.0" and current_line.split()[1] == "0.0.0.0":
        add_to_cache("Active route with 0.0.0.0")
    else:
        add_to_cache("No active route with 0.0.0.0")


    print("4. NTP \n")
    while "Pinging" not in current_line:
        read_line(file)
        if "NtpServer" in current_line:
            data += current_line.split(",")[-1] + "\n"
        if "Source:" in current_line:
            data += current_line.split(":")[-1]
    add_to_cache(data)
    data = ""


    print("\n5. Google Ping \n")
    #
    #The command below reopens the file before looking for strings to help with resiliency. It is used multiple times.
    #
    file = reopen(file)
    while "-----" not in current_line:
        read_line(file)
        #print(bytes(line, "utf-8"))
        if current_line == '0 \n':
            add_to_cache("Ping succeeded")
        elif current_line == '1 \n':
            add_to_cache("ping did not succeed")


    print("6a. Local Users \n")
    while "command completed successfully" not in current_line:
        print(current_line)
        read_line(file)
    freeresponse()


    print("\n6b. Guest Account \n")
    file = reopen(file)
    try:
        while "User name                    Guest" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        if current_line.split()[-1] == "No":
            add_to_cache("Account exists \n not active")
        else:
            add_to_cache("Account exists \n is active")
    except Exception:
        print("Guest account was unable to be found. Continuing.....\n")
        add_to_cache("")
        pass

    file = reopen(file)

    print("\n6c. Admin Account \n")
    try:
        while "User name                    Administrator" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        if current_line.split()[-1] == "No":
            add_to_cache("Account exists \n not active")
        else:
            add_to_cache("Account exists \n is active")
    except Exception:
        print("Admin account was unable to be found. Continuing.....\n")
        add_to_cache("")
        pass

    file = reopen(file)


    print("\n7. Built-in Admins \n")
    while "Members" not in current_line:
        read_line(file)
    while "---" not in current_line:
        read_line(file)
    while "command completed successfully" not in current_line:
        print(current_line)
        read_line(file)
    freeresponse()
    file = reopen(file)
    read_line(file)
    print(current_line)


    print("\n8. Domain Admins \n")
    try:
        while "\"Domain Admins\"" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        while "---" not in current_line:
            read_line(file)
        while "command completed successfully" not in current_line:
            if EOF(file):
                raise Exception
            print(current_line)
            read_line(file)
        freeresponse()
    except Exception:
        print("Was not able to find Domain Admins. Continuing.....\n")
        add_to_cache("")
        pass

    file = reopen(file)
    """print("9. Enterprise Admins")
    try:
        while "\"Enterprise Admins\"" not in line:
            if EOF(file):
                raise Exception
            read(file)
        while "command completed successfully" not in line:
            if "HKEY" in line:
                raise Exception
            print(line)
            read(file)
        freeresponse()
    except Exception:
        print("Was not able to find Enterprise Admins. Continuing.....\n")
        listing("")
        pass
    file = reopen(file)
    """

    print("\n10. Domain Password Configs \n")
    try:
        while "\"Domain Password Configs\"" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        while "command completed successfully" not in current_line:
            read_line(file)
            if 'Minimum password age' in current_line:
                add_to_cache(current_line.split()[-1] + " days")
            if "Maximum password age" in current_line:
                add_to_cache(current_line.split()[-1] + " days")
            if "Minimum password length" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Length of password history maintained" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Lockout threshold" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Lockout duration" in current_line:
                add_to_cache(current_line.split()[-1] + " minutes")
            if "Lockout observation window" in current_line:
                add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find Domain Pass Configs. Continuing.....\n")
        add_to_cache("")
        pass
    file = reopen(file)


    print("Placeholder for GP result information. This might come in a later version \n")
    add_to_cache("")


    print("\n12. Local Password Configs \n")
    try:
        while "\"Local Password Configs\"" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        while "command completed successfully" not in current_line:
            read_line(file)
            if 'Minimum password age' in current_line:
                add_to_cache(current_line.split()[-1])
            if "Maximum password age" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Minimum password length" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Length of password history maintained" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Lockout threshold" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Lockout duration" in current_line:
                add_to_cache(current_line.split()[-1])
            if "Lockout observation window" in current_line:
                add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find Local Password Configs. Continuing.....\n")
        add_to_cache("")
        pass
    file = reopen(file)


    print("\n13. Security Log Details \n")
    try:
        while "maxSize" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        add_to_cache(current_line.split()[-1])
        while "Date:" not in current_line:
            read_line(file)
        add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find Security Log Details. Continuing......\n")
        add_to_cache("")
        add_to_cache("")
        pass
    file = reopen(file)


    print("Placeholder for patch information. This might come in a later version \n")
    add_to_cache("")


    print("\n16a. Null session enumeration of network shares\n")
    try:
        while "RestrictAnonymous    REG_DWORD" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find reg entry for null session enumeration. Continuing....\n")
        add_to_cache("")
        pass
    file = reopen(file)


    print("\n16b. LLMNR enabled\n")
    try:
        while "EnableMulticast" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find reg entry for if LLMNR was enabled. Continuing....\n")
        add_to_cache("No response")
        pass
    file = reopen(file)


    print("\n16c. EnableSMB1Protocol\n")
    try:
        while "EnableSMB1Protocol" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        read_line(file)
        current_line = current_line.strip()
        add_to_cache(current_line.split()[1])
    except Exception:
        print("Was not able to find the SMB versions used. Continuing....\n")
        add_to_cache("")
    file = reopen(file)


    print("\n16d. Require Security Signature\n")
    try:
        while "RequireSecuritySignature" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        read_line(file)
        current_line = current_line.strip()
        add_to_cache(current_line)
    except Exception:
        print("Was not able to find the SMB Signing in txt file. Continuing....\n")
        add_to_cache("")
    file = reopen(file)


    print("\n16e. LM Compatibility Level\n")
    try:
        while "LmCompatibilityLevel" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        read_line(file)
        current_line = current_line.strip()
        add_to_cache(current_line)
    except Exception:
        print("Was not able to find the LM Comptatibility Level in txt file. Continuing....\n")
        add_to_cache("")
    file = reopen(file)


    print("\n16f. Windows Store\n")
    try:
        while "RemoveWindowsStore" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find reg entry for Windows Store. Continuing....\n")
        add_to_cache("No reg entry")
        pass
    file = reopen(file)

    print("\n16g. Convenience Pin\n")
    try:
        while "value" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        add_to_cache(current_line.split()[-1])
    except Exception:
        print("Was not able to find reg entry for Convenience Pin. Continuing....\n")
        add_to_cache("No reg entry")
        pass
    file = reopen(file)

    print("16h. Print Spooler")
    try:
        while "Print Nightmare" not in current_line:
            if EOF(file):
                raise Exception
            read_line(file)
        read_line(file)
        read_line(file)
        read_line(file)
        read_line(file)
        current_line = current_line.strip()
        current_line = current_line.split()[0]
        add_to_cache(current_line)
    except Exception:
        print("Was not able to find the Print Spooler in txt file. Continuing....\n")
        add_to_cache("An error occurred or Print Spooler is not on the machine")
    file = reopen(file)


#Function for cells with free response
def freeresponse():
    data = input('What should be input into the cell? ')
    add_to_cache(data)


#This function to assist with netstat output and possibly anything else that writes to file based on user selected lines
def lineselect(lists):
    counter = 1
    for lines in lists:
        lines = lines.strip('\n')
        print("(" + str(counter) + ")    " + lines)
        counter += 1
    try:
        data = ""
        selection = input("What Lines Contain Interesting Data? Separate lines with commas: ")
        selection = selection.split(",")
        for pick in selection:
            string = lists[int(pick) - 1]
            data += string + "\n"
        add_to_cache(data)
    except Exception:
        print("Typo error occurred. Please try again \n")
        lineselect(lists)


#Used to reopen the file at the beginning. Helps with script resilience when the script is unable to find a string when looping through the file.
def reopen(file):
    global dirs
    file.close()
    outputs = open(dirs, "r")
    return outputs


#I'm using the readline a lot, so I just made a function for it
def read_line(file):
    global current_line
    current_line = file.readline()


#formats the parsed text to csv notation and stores it in a list
def add_to_cache(info):
    global output_cache
    output_cache += "\"" + info + "\","


#final command to dump the csv formatted text to a csv file
def output(cname):
    ofile = open("C:\\Temp\\ICS_Sec_Configs\\" + cname + ".csv", "w")
    global output_cache
    ofile.write(output_cache)


#totally original code that tells me if you've reached the EOF
def EOF(f):
    current_pos = f.tell()
    file_size = os.fstat(f.fileno()).st_size
    return current_pos == file_size


if __name__ == "__main__":
    file_loop(args.file)
    output(computer_name)
