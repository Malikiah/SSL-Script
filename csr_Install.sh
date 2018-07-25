tts=1800
read -ep "Is this a VPS : " vps
read -ep "Domains : " domain
read -ep "Country : " country
read -ep "State or Province : " stateprovince
read -ep "City : " city;read -ep "Organization/Company : " organization
read -ep "Email Address : " email

				#-----This Generates the CSR && Private on a VPS-----
if [ $(tr "[:upper:]" "[:lower:]" <<< $vps) == "yes" ] || [ $(tr "[:upper:]" "[:lower:]" <<< $vps) == "y" ]
		then 
			echo "Generating private key using cPanel API"
			echo "."
			echo "."
			echo "."

			keyID=$(uapi SSL generate_key keysize=2048 | grep id | cut -d\  -f 6 | cut -d\" -f 1)

			echo "Generating CSR key using cPanel API"
			echo "."
			echo "."
			echo "."

			csr=$(uapi SSL generate_csr domains="$domain" countryName="$country" stateOrProvinceName="$stateprovince" localityName="$city" organizationName="$organization" emailAddress="$email" key_id=$keyID | grep text | cut -d\" -f 2)
			
			tmpder=$(mktemp)
			openssl req -out $tmpder -outform DER -in <(echo -e $csr)
			sha256=$(openssl dgst -sha256 $tmpder | cut -d\  -f 2 | tr a-z A-Z)
			md5hash=$(openssl dgst -md5 $tmpder | cut -d\  -f 2 | tr a-z A-Z)
			unlink $tmpder
			
			echo -e "$csr"
			echo "$sha256"
			echo "$md5hash"
			echo "Capturing root directory for $domain..."
			echo "."
			echo "."
			echo "."

			rootdir=$(uapi DomainInfo domains_data | grep -Pzo "(?s)documentroot: ([^\n]*)\n *domain: $domain" | grep documentroot | cut -d\  -f 2)
			sha256=$(echo -e "$sha256\ncomodoca.com")
			mkdir -p "$rootdir"/.well-known/pki-validation
			echo -e "$sha256" >  "$rootdir"/.well-known/pki-validation/"$md5hash".txt
			
			echo "Validating access..."
			check=$(curl -A . -s  "$domain"/.well-known/pki-validation/"$md5hash".txt)
			
		if [ "$sha256" == "$check" ]
				then echo -e 'Your pki-validation is ready!' "\n$check"
				
				else 
					mv "$rootdir"/.htaccess "$rootdir"/.htaccess_DISABLED
					
					echo "Validating access..."
					check=$(curl -A . -s  "$domain"/.well-known/pki-validation/"$md5hash".txt)
					
					echo -e 'The .htaccess has been disabled re enabling in' "$tts"'s.\npki-validation is ready!' "\n$check"
					sleep "$tts"
					mv "$rootdir"/.htaccess_DISABLED "$rootdir"/.htaccess

		fi

		#-----This Generates the CSR && Private on a shared Server-----
else 
		
		read -ep "What is the root directory of $domain : " sharedRootDir
		
			echo "Generating private key using openssl"
			echo -e "."
			echo -e "."
			echo -e ".\n"
			openssl req -out ./ssl/csrs/"$domain".csr -new -newkey rsa:2048 -nodes -keyout ./ssl/keys/"$domain".key -subj "/C=$country/ST=$stateOrProvinceName/L=$city/O=$organization/CN=$domain"
			
			echo -e "Generating CSR key using openssl"
			echo -e "."
			echo -e "."
			echo -e ".\n"
			csr=$(cat ssl/csrs/"$domain".csr)
			
			tmpder=$(mktemp)
			openssl req -out $tmpder -outform DER -in <(echo -e $csr)
			sha256=$(openssl dgst -sha256 $tmpder | cut -d\  -f 2 | tr a-z A-Z)
			md5hash=$(openssl dgst -md5 $tmpder | cut -d\  -f 2 | tr a-z A-Z)
			unlink $tmpder
			
			echo -e "\n$csr\n"
			echo -e "$sha256"
			echo -e"$md5hash"
			echo -e "Capturing root directory for $domain...\n"
			echo -e "."
			echo -e "."
			echo -e "."
			
			sha256=$(echo -e "$sha256\ncomodoca.com")
			mkdir -p "$sharedRootDir"/.well-known/pki-validation
			echo -e "$sha256" >  "$sharedRootDir"/.well-known/pki-validation/"$md5hash".txt
			
		check=$(curl -A . -s  "$domain"/.well-known/pki-validation/"$md5hash".txt)
		
		if [ "$sha256" == "$check" ]
			then echo -e 'Your pki-validation is ready!' "\n$check";
			
			
			
			else 
				mv ./"$sharedRootDir"/.htaccess ./"$sharedRootDir"/.htaccess_DISABLED
				echo "Validating access..."
				check=$(curl -A . -s  "$domain"/.well-known/pki-validation/"$md5hash".txt)
					if [ "$sha256" == "$check" ]
						then 
						echo -e 'Your pki-validation is ready!' "\n$check";
						else
							echo "CANNOT COMPLETE DCV!!!" 
							mv ./"$sharedRootdir"/.htaccess_DISABLED ./"$sharedRootDir"/.htaccess
							break
					fi
				echo -e 'The .htaccess has been disabled re enabling in' "$tts"'s.\npki-validation is ready!' "\n$check"
				sleep "$tts"
				mv ./"$sharedRootdir"/.htaccess_DISABLED ./"$sharedRootDir"/.htaccess

		fi

fi
