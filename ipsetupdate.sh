#!/bin/zsh

# Created by Joe Bloggs [2017-08-27 Sun]

## Script to add IP addresses/networks to an ipset.
## See USAGE string below.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.
# If not, see <http://www.gnu.org/licenses/>.

# location of ipset binary
IPSET=/sbin/ipset
# Set initial default values
SETNAME=
SETTYPE=
DEFAULTSETTYPE="hash:net"
APPENDONLY=
LIST=
# USAGE STRING
USAGE="Usage: ipsetupdate.sh -n <NAME> [-h|-l] [-p] [-c \"<OPTS>\"] [-a \"<OPTS>\"] [-i \"<ELEM>..\"] [-f \"<FILE>..\"] [-u \"<URL>..\"]
where: 

 -h            = show this help
 -l	       = list information about existing ipsets 
 -n <NAME>     = name of ipset to create/add to (if it doesnt yet exist it will be created)
 -t <TYPE>     = type of ipset, default is \"${DEFAULTSETTYPE}\"
 -p            = append only (dont flush the ipset before adding)
 -c \"<OPTS>\"   = options for 'ipset create' (see ipset manpage)
 -a \"<OPTS>\"   = options for 'ipset add' (see ipset manpage)
 -i \"<ELEM>..\" = list of elements to add to the ipset (IP/MAC addresses, ports, etc - see ipset manpage)
 -f \"<FILE>..\" = list of files containing elements to add to the ipset (one element per line)
 -u \"<URL>..\"  = list of URLs to webpages containing elements to add to the ipset (one element per line)

Note: domain names may be used instead of IP addresses in which case a reverse DNS lookup will be performed and 
      elements for each corresponding IP address will be added.
      For example imap.google.com,tcp:993 would be replaced by: 74.125.71.108,tcp:993 and 74.125.71.109,tcp:993
      Also lines starting with # or ; in files or webpages will be treated as comments and ignored\n"

# arrays
typeset -a CREATEOPTS ADDOPTS ELEMS FILES URLS
# quit if no arguments passed print $USAGE
if [[ "$#" -lt 1 ]]; then
    echo "${USAGE}"
    exit 1
fi
# PARSE COMMAND LINE OPTIONS.
## Variables: OPTIND=index of next argument to be processed, OPTARG=set to current option argument
## Place a colon after every option that has an argument (initial colon means silent error reporting mode)
while getopts "hlpn:t:c:a:i:f:u:" option; do
    case $option in
	(h)
	    echo "$USAGE"
	    exit
	    ;;
	(l)
	    LIST=1
	    ;;
        (\?)
	    echo "$USAGE"
	    exit 1
	    ;;
      	(p)
	    APPENDONLY=1
	    ;;
	(n)
	    SETNAME="${OPTARG}"
	    ;;
	(t)
	    SETTYPE="${OPTARG}"
	    ;;
	(c)
	    CREATEOPTS="${(z)OPTARG}"
	    ;;
	(a)
	    ADDOPTS="${(z)OPTARG}"
	    ;;
	(i)
	    ELEMS="${(z)OPTARG}"
	    ;;
	(f)
	    FILES="${(z)OPTARG}"
	    ;;
	(u)
	    URLS="${(z)OPTARG}"
	    ;;
	(*)
	    echo "Invalid option"
	    exit 1
	    ;;
    esac 
done

# If called with -l option just list the ipsets in a table
if [ -n "${LIST}" ]; then
    FORMATSTR="%-10s %-20s %-10s %-10s %-10s\n"
    printf "${FORMATSTR}" "NAME" "TYPE" "NUM ELEMS" "MAX ELEMS" "MEMSIZE (BYTES)"
    TOTALNUM=0
    TOTALMEM=0
    TOTALMAX=0
    for name in $($IPSET -n list); do
	IPSETINFO="$($IPSET list ${name} 2>/dev/null)"
	if [[ "$?" -eq 0 ]]; then
	    IPSETTYPE="${${IPSETINFO##*Type: }//$'\n'Revision*}"
	    IPSETNUM="${IPSETINFO:+$(($(echo ${IPSETINFO##*Members:}|wc -l)-1))}"
	    IPSETMAX="${${IPSETINFO##*maxelem }//$'\n'Size in memory*}"
	    IPSETMEM="${${IPSETINFO##*memory: }//$'\n'References*}"
	    TOTALNUM=$(( $IPSETNUM + $TOTALNUM ))
	    TOTALMEM=$(( $IPSETMEM + $TOTALMEM ))
	    TOTALMAX=$(( $IPSETMAX + $TOTALMAX ))
	else
	    IPSETTYPE="---"
	    IPSETNUM="---"
	    IPSETMEM="---"
	    IPSETMAX="---"
	fi
	printf "${FORMATSTR}" "${name}" "${IPSETTYPE}" "${IPSETNUM}" "${IPSETMAX}" "${IPSETMEM}"
    done
    printf "${FORMATSTR}" "TOTAL:" "---" "${TOTALNUM}" "${TOTALMAX}" "${TOTALMEM}"
    exit
fi

# check we have a name for the ipset 
if [ -z "${SETNAME}" ]; then
    echo "Error: a name (-n) argument must be supplied

$USAGE"
    exit 1
fi
# check we have some ipsets to add
if [ -z "${ELEMS}" ] && [ -z "${FILES}" ] && [ -z "${URLS}" ]; then
    echo "Error: IP addresses, filenames or URLs must be supplied

$USAGE"
    exit 1
fi
# HELPER FUNCTIONS
## Function to check if any of a list of programs (passed as args to function) is installed.
## The first program in the arguments list that is installed will be printed. If none are installed
## then it will exit the script with an error (after printing a message).
checkinstalled() {
    for cmd in "${@}"; do
	instcmd="$(which ${cmd} 2>/dev/null)"
	if [[ "$?" -eq 0 ]]; then
	    echo "${instcmd}"
	    return 0
	fi
    done
    echo "Cannot find: ${@}"
    echo "Run \"apt-get install ${@}\""
    exit 1
}

## Check that ipset is installed.
checkinstalled $IPSET >/dev/null
# check for a reverse DNS lookup command.
DNSCMD="$(checkinstalled dig nslookup host)"
## Function which prints a list of IP addresses corresponding to a list of domain names (given as args).
## All IP addresses are printed, even if some domains have more than one.
reversedns() {
    for host in "${@}"; do
	# do the reverse DNS lookup
	if [[ "${DNSCMD}" =~ dig ]]; then
	    "${DNSCMD}" +short "${host}" | grep '^[0-9.]\+$'
	elif [[ "${DNSCMD}" =~ host ]]; then
	     "${DNSCMD}" "${host}" | awk -e '/has address/ {print $4}'
	elif [[ "${DNSCMD}" =~ nslookup ]]; then
	     "${DNSCMD}" "${host}" | awk -e '/^Address: / { print $2 }'
	else
	    echo "Invalid reverse DNS lookup command!"
	    exit 1
	fi	    
    done
}


# create the new set if it doesnt already exist
if ! $IPSET -q list "${SETNAME}" >/dev/null ; then
    # set the typename to default value if not already set
    if [ -z "${SETTYPE}" ]; then
	SETTYPE="${DEFAULTSETTYPE}"
    fi
    $IPSET create ${SETNAME} ${SETTYPE} ${CREATEOPTS[@]}
    APPENDONLY=1
else
    # if it already exists then check that the types match
    OLDSETTYPE="${${$($IPSET -t list ${SETNAME})##*Type: }%%$'\n'*}"
    if [ -z "${SETTYPE}" ]; then
	SETTYPE="${OLDSETTYPE}"
    elif [ "${SETTYPE}" != "${OLDSETTYPE}" ]; then
	echo "Incompatible typename ${SETTYPE} for existing ipset ${SETNAME} of type ${OLDSETTYPE}"
	exit 1
    fi
fi

# some regexps for matching elements
DOMAINRX="([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})"
MACRX="(([0-9a-fA-F][0-9a-fA-F]:){5}[0-9a-fA-F][0-9a-fA-F])"
MASKRX="([0-9]|[0-2][0-9]|3[0-2])"
PORTRX="([0-9]{1,5})"
PROTORX="[a-z-]+"
IFACERX="(physdev:)?[a-z0-9]{2,15}"
IPV4RX="([0-9]{1,3}(\.[0-9]{1,3}){3}(/${MASKRX})?)"
IPV6RX="(([0-9a-fA-F]{0,4}:){2,7}(:|[0-9a-fA-F]{1,4})(/${MASKRX})?)"
IPV4RX2="${IPV4RX}(-${IPV4RX})?"
IPV6RX2="${IPV6RX}(-${IPV6RX})?"
IPRX="(${IPV4RX2}|${IPV6RX2}|${DOMAINRX})"
PORTRX2="(${PROTORX}:)?${PORTRX}(-${PORTRX})?"

# create regexp to match elements for this type of ipset
ELEMRX="${${${${${SETTYPE#*:}//(ip|net)/${IPRX}}//mac/${MACRX}}//port/${PORTRX2}}//iface/${IFACERX}}"

# Add elements from FILES and URLS
if [ -n "$FILES" ]; then
   for file in "${FILES[@]}"; do
       # remove duplicated and commented lines before extracting elements
       ELEMS+=("${(f)$(sort -u <${file}|sed 's/ *[;#].*//g'|egrep ${ELEMRX})}")
   done
fi
if [ -n "$URLS" ]; then
    URLCMD="$(checkinstalled curl wget)"
    for url in "${URLS[@]}"; do
	if [[ "${URLCMD}" =~ curl ]]; then
	    ELEMS+=("${(f)$(${URLCMD} -L -v -s -k ${url} 2>/dev/null|sed 's/ *[;#].*//g'|egrep ${ELEMRX})}")
	elif [[ "${URLCMD}" =~ wget ]]; then
	    ELEMS+=("${(f)$(${URLCMD} -qO- ${url} 2>/dev/null|sed 's/ *[;#].*//g'|egrep ${ELEMRX})}")
	else
	    echo "Invalid URL download command!"
	    exit 1
	fi
    done
fi


# Convert ALL domain names to IP addresses
NEWELEMS=()
for elem in "${ELEMS[@]}"; do
    if [[ "${elem}" =~ "${DOMAINRX}" ]]; then
	DOMAIN="${MATCH}"
	for addr in $(reversedns "${DOMAIN}"); do
	    elem2="${elem//${DOMAIN}/${addr}}"
	    # check again for a 2nd domain
	    if [[ "${elem2}" =~ "${DOMAINRX}" ]]; then
		for addr2 in $(reversedns "${MATCH}"); do
		    NEWELEMS+="${elem2//${MATCH}/${addr2}}"
		done
	    else
		NEWELEMS+="${elem2}"
	    fi
	done
    else
	NEWELEMS+="${elem}"
    fi
done

# exit if there are no items for the ipset
if [ "${#NEWELEMS}" -eq 0 ]; then
    echo "No IP addresses/networks were found"
    exit 1
fi

# If we dont need to replace the existing ipset then we can just add elements to it.
if [ -n "${APPENDONLY}" ]; then
    for elem in "${NEWELEMS[@]}"; do
	if ! $IPSET test ${SETNAME} ${elem} 2>/dev/null ; then
	    $IPSET add ${SETNAME} ${elem} ${ADDOPTS[@]}
	fi
    done
else
    # To replace an existing ipset we will create a temporary one, add elements to it,
    # and then swap it with the old one to guarantee an atomic update. 
    
    # temporary ipset name
    TMP_SETNAME="tmp_$$"
    # create the temporary ipset
    $IPSET create ${TMP_SETNAME} ${SETTYPE} ${CREATEOPTS[@]}
    # add elements to it
    for elem in "${NEWELEMS[@]}"; do
	if ! $IPSET test ${TMP_SETNAME} ${elem} 2>/dev/null ; then
	    $IPSET add ${TMP_SETNAME} ${elem} ${ADDOPTS[@]}
	    if [[ "$?" -eq 1 ]]; then	    
		$IPSET destroy ${TMP_SETNAME}
		exit 1
	    fi
	fi
    done
    # overwrite old ipset with the temp one
    $IPSET swap ${TMP_SETNAME} ${SETNAME}
    # destroy the temporary ipset
    $IPSET destroy ${TMP_SETNAME}
fi
