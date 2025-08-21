# Homelab
VirtualBox VMs including servers, clients, attacker, and domain controller simulating an attack on an enterprise network.

## Objective

This home lab consists of an end-to-end attack on a simulated corporate environment which includes all the components that make up an enterpise network including a Windows 11 Enterprise Workstation, Ubuntu Desktop, Security Workstation running Security Onion, Security Email Server, Ubuntu Security Server running Wazuh SIEM+XDR, and an Active Directory Services Server.  

### Skills Learned
- Provisioning Permissions
- Intrusion Detection
- Log Analysis
- Vulnerability Detection
- Compliance Reporting
- Reconnaisance
- Initial Access
- Lateral Movement
- Privilege Escalation
- Data Exfiltration
- Persistence

### Tools Used
- Active Directory (DNS, DHCP, SSO)
- Wazuh (SIEM, XDR, Vulnerability Scanner)
- Mailhog (email-testing, SMTP)
- Evil-WinRM (Penetration Testing)
- Hydra (Password Cracking)
- SecLists (Penetration Testing)
- NetExec (Remote C2)
- XFreeRDP (RDP Exploit)

## Steps
![image](https://github.com/user-attachments/assets/6a769eab-393b-40bf-ae63-cf11ed459b8a)

*Active Directory Domain Service Domain Controller corp.homelab-dc.com configured with IP address 10.0.0.5.*

![image](https://github.com/user-attachments/assets/05ec0635-da2b-4778-9d41-5effc1495c0d)

*Users joined to the domain highlighted.*

![image](https://github.com/user-attachments/assets/ad4377f8-ab93-4dad-b3cf-661bdf179eb8)

*John Doe Account Properties*

![image](https://github.com/user-attachments/assets/bace7efd-6cc4-4ad3-b41b-84c11cf365d1)

*Jane Doe Account Properties*

![image](https://github.com/user-attachments/assets/2ea762ae-7401-4b54-8ef3-8c515887736c)

*Administrator Account Properties*

![image](https://github.com/user-attachments/assets/5afaef7a-f519-482f-864f-fecb1e697f96)

*Email Server Account Properties (showing joined to domain)*

![image](https://github.com/user-attachments/assets/162aae2f-5f10-4f65-9efc-6ac48b29e558)

*Computers joined to domain highlighted*

![image](https://github.com/user-attachments/assets/4cf4a9a1-5214-4b4d-b95b-b9cf62b814c1)

*Corporate Server joined to domain*

![image](https://github.com/user-attachments/assets/6c42ec31-8800-48cf-88f3-3af4647c4e59)

*Email Server joined to domain*

![image](https://github.com/user-attachments/assets/226b842d-59c6-49e5-a1ba-2063aa4faee0)

*Linux Client Workstation joined to domain*

![image](https://github.com/user-attachments/assets/4ca416d8-a641-47a1-a69e-45fa3d0b9cd7)

*Ubuntu Security Workstation joined to domain*

![image](https://github.com/user-attachments/assets/ec47ad3f-3686-463b-90c4-f7f28aca8555)

*Windows Client Workstation joined to domain*

![image](https://github.com/user-attachments/assets/4ace4677-d902-4d9d-9fc4-423eeec4e21e)

*Test message from Corporate Server to Jane Doe Linux Client Workstation using Mailhog*

![image](https://github.com/user-attachments/assets/6b0ba66a-6af3-4bc6-b90b-4b94bf55bd43)

*Mailhog confirm capture redirected from SMTP listen port 1025 to 8025 (see URL)*

![image](https://github.com/user-attachments/assets/21fdb850-110c-4f1c-877d-864b12d44c9d)

*Email poller script on Linux Client*

![image](https://github.com/user-attachments/assets/6ff80fe0-70cd-464d-94e3-dd541a6a682a)

*All agents connected to Wazuh*

![image](https://github.com/user-attachments/assets/cc1da91c-52e3-46b5-b2ac-cb957aaab30a)

*Windows and Linus groups created*

![image](https://github.com/user-attachments/assets/31243a8e-d22b-4f96-a689-3763ceeabac7)

*Linux Client agent added to Linus group*

![image](https://github.com/user-attachments/assets/d1baf046-a568-4eeb-9829-ebb2726b50aa)

*Windows Client and Windows Domain Controller agents added to Windows group*

![image](https://github.com/user-attachments/assets/2a9a38fd-6e96-4026-8d70-48e8e1844801)

*Linux group configuration file*

![image](https://github.com/user-attachments/assets/5af7fcc1-3c17-4d77-b3a6-29d7fa6281cb)

*Windows group configuration file*

![image](https://github.com/user-attachments/assets/35544f57-742d-4ca9-abc1-6e6d9f35039f)

*RDP enabled on Domain Controller*

![image](https://github.com/user-attachments/assets/2ab71b35-aa1e-43e2-b71a-a2967f812f53)

*secrets.txt file created for later exploit*

![image](https://github.com/user-attachments/assets/91fd0aec-6d1a-46d8-a571-5a95f93193c7)

*Contents of secrets.txt*

![image](https://github.com/user-attachments/assets/184d1ece-332a-4c0d-a0f6-6fe41c967cc2)

*SSH started on attacker machine*

![image](https://github.com/user-attachments/assets/1f1644e4-5b5e-4c21-bc1d-d7f14a4ed3a0)

*Failing SSH attempt*

![image](https://github.com/user-attachments/assets/927bbaaa-3278-41e7-b75c-240f6b4a11e5)

*Wazuh alert*

![image](https://github.com/user-attachments/assets/2035f22d-d1d0-4317-b04d-606f8645b42b)

*More alert details showing sec-box manager.name field, description, etc

![image](https://github.com/user-attachments/assets/a2911d55-138d-4eea-9440-7f7563b399ef)

*Creating monitor*

![image](https://github.com/user-attachments/assets/4717c4c2-80dc-40ac-b21f-1275af3ead3a)

*Creating monitor continued*

![image](https://github.com/user-attachments/assets/43f187de-eb9f-4c60-a52e-cf9300bcb60c)

*Creating monitor continued*

![image](https://github.com/user-attachments/assets/d2f242aa-23a1-49a3-8b11-c788074d1ef6)

*Shows monitor triggered*

![image](https://github.com/user-attachments/assets/4df98a08-1ac9-461f-b29b-e62f3c5ec6b3)

*WinRM Logon monitor creation*

![image](https://github.com/user-attachments/assets/8675b283-b90a-4251-9f7e-c208a270d7e1)

*WinRM Logon monitor creation continued*

![image](https://github.com/user-attachments/assets/7a105963-5523-4fe1-b87f-e4d7209adfb0)

*File integrity monitoring Domain Controller agent before file edit*

![image](https://github.com/user-attachments/assets/6e084fe5-ded2-4dd6-978e-ea36329e08bf)

*Edited file*

![image](https://github.com/user-attachments/assets/1e1ba1b8-0fa1-4055-bf25-9d5db9f7d944)

*Event showing secret.txt file modification*

![image](https://github.com/user-attachments/assets/4c0e515a-45ae-4895-9558-cd487753c595)

*New rule added to local_rules.xml to specifically monitor modification to secrets.txt*

![image](https://github.com/user-attachments/assets/ab643707-4f9b-4dbc-856c-54a9d126194d)

*Port 22 ssh is open*

![image](https://github.com/user-attachments/assets/ef7850d3-1a19-445c-8dd4-a136da455f9b)

*Extracted rockyou.txt wordlist and added to home directory to use in hydra attack*

![image](https://github.com/user-attachments/assets/fae8f216-8f81-405c-97d8-ba44b0f8de3d)

*Hydra output showing vulnerable host IP, login, and password*

![image](https://github.com/user-attachments/assets/f5d8cc0d-4f54-4392-811f-9ea2b62c85c5)

*Able to establish SSH session with root priveleges using exploited credentials (see root prompt)*

![image](https://github.com/user-attachments/assets/a4ebf219-2120-40ee-9d2d-70405fdf5481)

*High privelege ports shown open 8025 and 1025 (mailhog client)*

![image](https://github.com/user-attachments/assets/cded71ff-0c89-441c-8a26-453cc0901b48)

*Google results showing mail services on respective open ports*

![image](https://github.com/user-attachments/assets/ea1edfe5-1319-4490-a9a3-94211272ac16)

*Using that information entering in host IP and port renders Mailhog UI and mail.*

![image](https://github.com/user-attachments/assets/4b5527fd-b253-400c-98f9-cca4c97fd71e)

*PHP script added to /var/www/html directory*

![image](https://github.com/user-attachments/assets/2c6c61ff-a502-4a26-8282-da137b9bad05)

*index.html added to /var/www/html directory*

![image](https://github.com/user-attachments/assets/0ce03117-a961-49d2-a637-9ddf522396ef)

*index.html added to /var/www/html directory continued*

![image](https://github.com/user-attachments/assets/c56d855d-f410-46fe-8a9d-fb9124e7d0ce)

*Start apache2 service*

![image](https://github.com/user-attachments/assets/1ecf59a9-eae2-449d-aa23-2a0cfa18ee33)

*Visit localhost to render malicious landing page created by previously downloaded files*

![image](https://github.com/user-attachments/assets/bae77a8f-3fbb-494b-a7f6-34593af62720)

*Output rendered after entering credentials*

![image](https://github.com/user-attachments/assets/826db8a5-f35d-4694-b487-1f1a58427d39)

*Cat creds.log file output test credentials entered by attacker machine*

![image](https://github.com/user-attachments/assets/7b67bf9b-4e61-42f6-9449-67e5d4cdfe5f)

*Using SSH Corporate Server session, phishing email is pasted into send_email.py*

![image](https://github.com/user-attachments/assets/6f168885-b714-4fca-aaad-71d154c452f5)

*Email is sent via SSH session*

![image](https://github.com/user-attachments/assets/6ee3e335-401a-47b2-89a6-3ebd81a48a3e)

*Mailhog UI showing email in Jane's inbox*

![image](https://github.com/user-attachments/assets/52cf494d-465a-400e-bb7f-c9e4829e4959)

*Jane follows link and enters in her credentials*

![image](https://github.com/user-attachments/assets/f0dcd290-3c3a-439c-832b-11cc4ddeee11)

*Janes credentials harvested to creds.log file*

![image](https://github.com/user-attachments/assets/15e73dbc-4e2d-42d7-8b6d-571a13ff9c75)

*Able to SSH into Janes client machine*

![image](https://github.com/user-attachments/assets/7bc1b60a-38ab-4d57-987c-6b41fc9fa33a)

*NMAP scan showing WinRM ports enabled on Janes Linux Client*

![image](https://github.com/user-attachments/assets/ed17fd47-5aa4-4498-80bc-bf4bffef3732)

*Add Administrator to users.txt*

![image](https://github.com/user-attachments/assets/455956ca-424b-4d6d-8a71-6df44885f33e)

*Add P@ssw0rd to pass.txt*

![image](https://github.com/user-attachments/assets/cc9c0137-7c02-4480-b8af-23ed3107a0e6)

*Use previous creds with nxc to target WinRM service on Windows Client machine (10.0.0.100)*

![image](https://github.com/user-attachments/assets/ef5a6a74-4cd3-4211-b2cd-d6d9dc8c039a)

*Open-source tool evil-winrm grants powershell terminal administrator access via lateral movement from Linux Client to Windows Client*

![image](https://github.com/user-attachments/assets/347b50b2-e5eb-4e4e-83e7-49e38d883167)

*nltest /dsgetdc command shows domain name corp.homelab-dc.com*

![image](https://github.com/user-attachments/assets/536aeaac-575a-469e-ac8a-a60d894501bd)

*NMAP scan reveals port 3389 RDP open on domain controller*

![image](https://github.com/user-attachments/assets/5644058a-a99f-4813-ad5c-032b0efc073b)

*using the information gathered previously about the domain, xfreerdp /v:10.0.05 /u:Administrator /p:P@ssw0rd /d:corp.homelab-dc.com opens remote window into domain controller*

![image](https://github.com/user-attachments/assets/db8a6268-2e28-4d8c-a573-47d3b3af48e7)

*Use scp to exfiltrate secrets.txt into my_sensitive_file.txt*

![image](https://github.com/user-attachments/assets/3f5bb678-5f12-48e0-a928-36d9ba343dbb)

*secrets.txt contents exfiltrated into my_sensitive_file.txt*

![image](https://github.com/user-attachments/assets/050b7043-3d7d-4869-9cb2-2e93d77b28e5)

*homelab-user provisioned and added to Administrators localgroup and Domain Admins*

![image](https://github.com/user-attachments/assets/cfe014e0-b155-419c-807e-2fa9fdb7c871)

*/domain command shows homelab-user Local Group and Global Group Memberships status*

![image](https://github.com/user-attachments/assets/de981ec7-bfb2-45d8-95fc-6ccb4c037caa)

*reverse shell downloaded from Github repository*

![image](https://github.com/user-attachments/assets/ef10dc47-3471-4ee3-b7c9-4f3bfb92e6d8)

*reverse shell script pasted in AppData > Local > Microsoft > Windows*

![image](https://github.com/user-attachments/assets/10c3891f-3a27-40bb-add6-58e551f15865)

*command copied from guide*

![image](https://github.com/user-attachments/assets/63e200f2-2dbc-4750-ac93-67156f8e85ca)

*bypass allows powershell scheduled task everyday at 12:00*

![image](https://github.com/user-attachments/assets/c1154274-bb47-4d49-8642-06c3383b389a)

*listening on port 4444*

![image](https://github.com/user-attachments/assets/6a5b8539-9a2d-4153-b315-b9e4628a488a)

*navigate to directory with reverse shell script and execute*

![image](https://github.com/user-attachments/assets/d4e335e5-2f70-4ddb-adc8-25c1e5885620)

*established persistence reverse shell connection*

![image](https://github.com/user-attachments/assets/a5f78667-0d0d-448d-af89-f5f8eebd5869)

*Wazuh logs showing modification of secrets.txt file*

![image](https://github.com/user-attachments/assets/a0309fc4-6e29-4f0b-9956-8b28cad72e65)

*All Wazuh alerts functioning and triggering*
