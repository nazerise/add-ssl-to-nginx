#!/bin/bash
###########This script add SSL configuration to Nginx

### default values
ssl_directory="/etc/nginx/ssl"
temp_ssl_directory="/root/ssl"
temp_cert="cert.pem"
temp_privkey="privkey.pem"
nginx_directory="/etc/nginx"
vhost_directory="/etc/nginx/conf.d"
########

copy_cert() {
	if [ -d $ssl_directory ];then
		echo -e "\033[0;32mSSL Directory exists\033[0m"
	else
		echo -e "\033[0;31mSSL Directory DOES NOT exist\033[0m"
		mkdir $ssl_directory
	fi
	if [ -d $ssl_directory/old ];then
                echo -e "\033[0;32mOLDSSL Directory exists\033[0m"
        else
                echo -e "\033[0;31mOLD SSL Directory DOES NOT exist\033[0m"
                mkdir $ssl_directory/old
        fi

        read -e -i "$temp_ssl_directory" -p "Where is the Directory of new SSL(press Enter to continue): " input
        tmp_ssl_directory="${input:-$tmp_ssl_directory}"

	read -e -i "$temp_ssl_directory/temp_cert" -p "New Cert file(press Enter to continue): " input
        temp_cert="${input:-$temp_cert}"
	ssl_cert=$(echo $temp_cert | rev | cut -d/ -f 1 | rev)

	read -e -i "$temp_ssl_directory/temp_privkey" -p "New Private Key file(press Enter to continue):" input
        temp_privkey="${input:-$temp_privkey}"
	ssl_priv=$(echo $temp_privkey | rev | cut -d/ -f 1 | rev)
	
	cert_CN=$(openssl x509 -in $temp_cert -text -noout | grep Subject: | grep -wo CN=.* | awk -F '=' '{print $2}')
#####Check CN if get error
	echo $cert_CN |  egrep  ".*[a-z]|[1-9].*" > /dev/null 2>&1
	if [ "$?" = "0" ];then
		echo -e "\033[0;33mCopy newSSL in $ssl_directory\033[0m"
		cd $ssl_directory
		mv $(ls -l $ssl_directory | grep "^-" | awk '{print $9}') $ssl_directory/old
		cp $temp_cert $ssl_directory
		cp $temp_privkey $ssl_directory
		cd -  > /dev/null 2>&1
	else
		echo -e "\033[0;31mCertificate in NOT correct\033[0m"
		exit 0
	fi
}

nginx_config_ssl() {
#####find "http {" in nginx.conf
	http_line=$(cat  $nginx_directory/nginx.conf |grep -now  'http \+{' | awk -F ':' '{print $1}')
	insert_ssl_line=$(expr $http_line + 1)
	sed -ie ""$http_line"G" $nginx_directory/nginx.conf

sed -i ''"$http_line"' r /dev/stdin' $nginx_directory/nginx.conf  <<EOT
	ssl_session_timeout  10m;
	ssl_session_cache    shared:SSL:50m;
	ssl_session_tickets  off;
 

	# Mozilla Intermediate configuration
	ssl_protocols        TLSv1.2 TLSv1.3;

	ssl_ciphers          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

	ssl_prefer_server_ciphers on;

EOT

}


nginx_config_servername() {
####### find right server_name without # and test in nginx.cof
	cat $nginx_directory/nginx.conf | grep -nw  'server_name' | egrep -v "test|#" > /dev/null 2>&1
	if [ "$?" == "0" ];then
                echo -e "\033[0;32mFind server_name in nginx.conf\033[0m"
		file=$nginx_directory/nginx.conf
		nginx_config_https $file
        else
                echo -e "\033[0;31mNo server_name in nginx.conf \033[0m"
        fi

####### find right server_name without # and test in /etc/nginx/conf.d
	cat $vhost_directory/*.conf | grep -nw  'server_name' | egrep -v "test|#" > /dev/null 2>&1
	if [ "$?" == "0" ];then
#                echo -e "\033[0;32mFind server_name in conf.d\033[0m"
		ls  $vhost_directory | grep .conf$ > /tmp/vhost.txt
		while IFS= read -r vhost
	        do
			file=$vhost_directory/$vhost
                	echo -e "\033[0;32mFind server_name in $file\033[0m"
			nginx_config_https $file
		done</tmp/vhost.txt
	else
                echo -e "\033[0;31mNo server_name in conf.d \033[0m"
        fi
		

}

##### $1 ----> server_name line number, $2 ---> nginx config file
find_empty_line() {
	line=$(expr $1 + 1)
####### find if the line is empty or not
	while awk '{if(NR=='"$line"') print $0}' $2  | egrep  ".*[a-z]|[1-9].*" > /dev/null 2>&1
        do
####### find if "server {" includes the line or not
		awk '{if(NR=='"$line"') print $0}' $2  | grep  "server \+{" > /dev/null 2>&1
		if [ "$?" = "0" ];then
			insert_line=$(expr $line - 1)
		        sed -ie ""$insert_line"G" $2
			line=$insert_line
		fi
		line=$(expr $line + 1)
        done
}

find_http_listen_condition() {
	line_1=$1
	line_2=$1
	find="n"
####### find if "server {" includes the line or not
	while awk '{if(NR=='"$line_1"') print $0}' $2  | grep  -v "server \+{.*" > /dev/null 2>&1
	do
####### find if "listen 443 ssl http2;" includes the line or not
		awk '{if(NR=='"$line_1"') print $0}' $2  | egrep  -v "#" | egrep "listen" | egrep   "443|ssl|http2"  > /dev/null 2>&1
		if [ "$?" = "0" ];then
			find="t"
			break
		fi
		line_1=$(expr $line_1 - 1)
	done

####### find if "server {" includes the line or not
	while awk '{if(NR=='"$line_2"') print $0}' $2  | grep  -v "server \+{.*" > /dev/null 2>&1
	do
####### find if "listen 443 ssl http2;" includes the line or not
		awk '{if(NR=='"$line_2"') print $0}' $2  | egrep  -v "#" | egrep "listen" | egrep  "443|ssl|http2"  > /dev/null 2>&1
		if [ "$?" = "0" ];then
			find="t"
			break
		fi
		line_2=$(expr $line_2 + 1)
	done
}

##### $1 ---> nginx config file
nginx_config_https() {
####### find server_name line number in nginx config file without test and #
	server_name_lines=$(cat $1 |  grep -now  '.*server_name.*' | egrep -v "test|#" | awk -F ':' '{print $1}' | sort -rn)
	list_server_name_lines=( $( echo $server_name_lines ) )
	for i in ${list_server_name_lines[@]}
	do

####### find domain in server_name nginx config file without test and #
		server_name_value=$(awk '{if(NR=='"$i"') print $0}' $1  |  awk -F 'server_name' '{print $2}')
		find_empty_line $i $1
		empty_line=$line

############find listen port 80 line in nginx config file
		find_http__listen_condition $empty_line $1

############check if certificate match with server_name
	        echo $server_name_value | egrep -wv ".*\..$cert_CNi;" > /dev/null 2>&1
        	if [ "$?" = "0" ];then
			if [ $find != "t" ]; then
###########donot run if find port 443 or ssl or http2
				echo -e "\033[0;33mAppend SSL config to $1 file for Server $server_name_value \033[0m"
sed -i ''"$empty_line"' r /dev/stdin' $1 <<EOT
	return 301 https://\$host\$request_uri;
	}

     server{
        listen 443 ssl http2;
        server_name $server_name_value
	ssl_certificate $ssl_directory/$ssl_cert;
	ssl_certificate_key $ssl_directory/$ssl_priv;

EOT
			fi

		fi
	done

}

check_nginx() {
        nginx -t
        if [ "$?" != "0" ];then
                echo -e "\033[0;31mNginx is Not Running \033[0m"
        else
                echo -e "\033[0;32mNginx Running Successfully \033[0m"
                nginx -s reload
        fi

}


########## fundtion that will be run ########

copy_cert
#### comment nginx_config_ssl function if SSL protocols was added to nginx.conf before
#nginx_config_ssl
nginx_config_servername
check_nginx
