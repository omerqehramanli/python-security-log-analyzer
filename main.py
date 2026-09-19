import ipaddress
from datetime import datetime, timedelta

with open("security.log") as file:
    failed_count = 0
    failed_ips = {}
    last_seen = {}
    bruteforce_alerts = 0
    bruteforce_ips = {}
    blocked_ips = []

    for line in file:
        if "FAILED" in line:
            failed_count +=1

            a=line.split()
            timestamp = a[0] + " " + a[1]
            log_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            ip=(a[6])
            if ip in last_seen:
                previous_time = last_seen[ip]
                time_difference = log_time - previous_time
           
                if time_difference <= timedelta(minutes=5):
                    print(f"BRUTE-FORCE ALERT: {ip} - {time_difference}")
                    bruteforce_alerts += 1

                    if ip in bruteforce_ips:
                        bruteforce_ips[ip] += 1
                    else:
                        bruteforce_ips[ip] = 1

            last_seen[ip] = log_time
            

            ip_obj = ipaddress.ip_address(ip)


            if ip in failed_ips:
                failed_ips[ip] += 1
            else:
                failed_ips[ip]=1

     

    print("\n========== SECURITY REPORT ==========")
    most_failed_ip = max(failed_ips, key=failed_ips.get)

    print(f"Most Failed IP: {most_failed_ip}")
    print(f"Failed Attempts: {failed_ips[most_failed_ip]}")

    print(f"Total Failed Attempts: {failed_count}")
    print(f"Brute-Force Alerts: {bruteforce_alerts}")

    print("\nSuspicious IPs:")

    for ip, count in bruteforce_ips.items():
        print(f"{ip} -> {count} brute-force alerts")

    

    print("\nIP ANALYSIS:")

    for ip, count in failed_ips.items():
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            status = "PRIVATE"
        else:
            status = "PUBLIC"

        if count >= 5:
            risk = "HIGH"
        elif count >= 3:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        if risk == "HIGH":
            decision = "BLOCK"
        elif risk == "MEDIUM":
            decision = "INVESTIGATE"
        else:
            decision = "ALLOW"

        if decision == "BLOCK":
            blocked_ips.append(ip)

        print(f"{ip}")
        print(f"    Status: {status}")
        print(f"    Failed Attempts: {count}")
        print(f"    Risk: {risk}")
        print(f"    Decision: {decision}")
        

    if blocked_ips:
        for ip in blocked_ips:
            print(f"{ip} -> BLOCKED")
    else:
        print("No IPs blocked")


    with open("security_report.txt", "w") as report:
        report.write("SECURITY REPORT\n")
        report.write("====================\n")
        report.write(f"Most Failed IP: {most_failed_ip}\n")
        report.write(f"Failed Attempts: {failed_ips[most_failed_ip]}\n")
        report.write(f"Total Failed Attempts: {failed_count}\n")
        report.write(f"Brute-Force Alerts: {bruteforce_alerts}\n")
        report.write("\nSuspicious IPs:\n")

        for ip, count in bruteforce_ips.items():
            report.write(f"{ip} -> {count} brute-force alerts\n")

        report.write("\nIP ANALYSIS:\n")

        for ip, count in failed_ips.items():
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_private:
                status = "PRIVATE"
            else:
                status = "PUBLIC"

            if count >= 5:
                risk = "HIGH"
            elif count >= 3:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            if risk == "HIGH":
                decision = "BLOCK"
            elif risk == "MEDIUM":
                decision = "INVESTIGATE"
            else:
                decision = "ALLOW"

            report.write(f"\n{ip}\n")
            report.write(f"    Status: {status}\n")
            report.write(f"    Failed Attempts: {count}\n")
            report.write(f"    Risk: {risk}\n")
            report.write(f"    Decision: {decision}\n")
        report.write("\nBLOCKED IPS:\n")

        if blocked_ips:
            for ip in blocked_ips:
                report.write(f"{ip} -> BLOCKED\n")
        else:
            report.write("No IPs blocked\n")

        
        

        
          



