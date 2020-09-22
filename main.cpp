#include <iostream>
#include <string>
#include <stdio.h>
#include <pcap.h>
#include <sqlite3.h>
#include <time.h>  

/* GLOBAL DEFINITIONS */
#define MST (-7)
#define UTC (0)
#define CCT (+8)
#define CDT (-5)

/* --- NAMESPACE DECLERATION --- */
using namespace std;

/* --- FUNCTION DECLERATION --- */
int initNetworkListener(int selectedDevNum);
int run_sniffer(pcap_t *handle);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int initSQLite(string s);
static int sqlitecb_expose(void *NotUsed, int argc, char **argv, char **azColName);
static int sqlite_clearcb();
string seconds_to_datetime(struct tm * ptm);


/* --- GLOBAL VARIABLES --- */
const string TABLE_NAME = "BW_MONITOR";
static int sqlite_argc;
static char **sqlite_argv, **sqlite_azColName;

/* --- GLOBAL FUNCTIONS --- */
int main(int argc, char *argv[])
{
	int devNum = -1;
	
	if(argc == 2) {
		devNum = argv[0][0]-46;
	}

	initSQLite("bwmonitor.db");
	initNetworkListener(devNum);

	return(0);
}

int initSQLite(string s) {
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	string sql;

	rc = sqlite3_open(s.c_str(), &db);

	if( rc ) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return(0);
	} else {
		fprintf(stderr, "Opened database successfully\n");
	}

	/* CHECK IF TABLE EXISTS */
	sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + TABLE_NAME + "';";
	sqlite_clearcb();
	rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &zErrMsg);
	cout << "size: " << sqlite_argc << endl;

	/* CREATE TABLE */
	if(rc == 0) { 
		sql = "CREATE TABLE " + TABLE_NAME + "("  \
			"ID INT PRIMARY KEY     NOT NULL," \
			"LENGTH            INT     NOT NULL," \
			"TIME_STAMP        CHAR(50));";

		/* Clear Output & Execute SQL statement */
		sqlite_clearcb();
		rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &zErrMsg);
		
		if( rc != SQLITE_OK ){
			fprintf(stderr, "SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
		} else {
			fprintf(stdout, "Table '%s' created successfully\n", TABLE_NAME);
		}
	}

	sqlite3_close(db);
	
	return 0;
}

static int sqlite_clearcb() {
	sqlite_argc = 0;
	sqlite_argv = NULL;
	sqlite_azColName = NULL;

	return 0;
}

static int sqlitecb_expose(void *NotUsed, int argc, char **argv, char **azColName) {

	sqlite_argc = argc;
	sqlite_argv = argv;
	sqlite_azColName = azColName;

	for(int i = 0; i<argc; i++) {
		cout << azColName[i] << " = " << argv[i] << endl;
	}
	return 0;
}

int initNetworkListener(int selectedDevNum) {
	/* ======================= */
	/* === SELECT A DEVICE === */
	/* ======================= */
	//Declare Variables
	pcap_if_t *alldevs, *temp, *selectedDev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int dev = pcap_findalldevs(&alldevs, errbuf);
	int i = 0;

	if(selectedDevNum == -1) {
		//Display all network devices
		cout << "Network interfaces present:" << endl;
		for(temp=alldevs;temp;temp=temp->next)
		{
			cout << i++ << " : " << temp->name << endl;
		}

		//Get desired network device from user
		cout << "Please choose a network device (0- " << i << "): ";
		cin >> selectedDevNum;
	}
	i = 0;
	for(temp=alldevs;temp;temp=temp->next)
	{
		if(i == selectedDevNum) {
			selectedDev = temp;
			break;
		}

	}
	cout << "Selected device is " << selectedDev->name << endl;
	
	//Open selected network device
	pcap_t *handle;
	handle = pcap_open_live(selectedDev->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", selectedDev, errbuf);
		return(2);
	}
	cout << selectedDev->name << " opened" << endl;


	/* ======================= */
	/* === SNIFF ON DEVICE === */
	/* ======================= */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 443";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	/* Find the properties for the device */
	if (pcap_lookupnet(selectedDev->name, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", selectedDev->name, errbuf);
		net = 0;
		mask = 0;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	run_sniffer(handle);

	/* And close the session */
	pcap_close(handle);
	return(0);
}

int run_sniffer(pcap_t* handle) {

	const u_char *packet;		/* The actual packet */
	struct pcap_pkthdr header;	/* The header that pcap gives us */

	while(1) {
		cout << "." << endl;
		/* Loop packets */
		pcap_loop(handle, 10, got_packet, NULL);
	}
	return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	cout << "Jacked packet | ";
	time_t rawtime = time(NULL);

	string datetime = seconds_to_datetime(gmtime(&rawtime));

	cout << "size is " << header->len << "bytes | time is " 
		<< datetime << "" << endl;
}

/**
  *	Convert time in seconds to string datetime
  *	datetime format is YYYY-MM-DD HH:MM:SS
  *
  * @param (struct tm)ptm
  * @return (string)datetime
  */
string seconds_to_datetime(struct tm * ptm) {
	int inttm_y = (ptm->tm_year+1900);
	int inttm_mo = (ptm->tm_mon+1);
	int inttm_d = (ptm->tm_mday);
	int inttm_h = (ptm->tm_hour+CDT);

	/* hour overflow | correct day */
	if(inttm_h < 0) {
		inttm_h += 24;
		inttm_d -= 1;
	}

	/* day overflow | correct month */
	if(inttm_d < 0) {
		inttm_d += 31;
		inttm_mo -= 1;
		/* Correct days 31/30/28/29 */
		if(inttm_mo == 4 || inttm_mo == 6 || inttm_mo == 9 || inttm_mo == 11)
			inttm_d -= 1; // For months w/ 30 days
		if(inttm_mo == 2) {
			if(inttm_y%4 == 0) // for feb leap year
				inttm_d -= 2;
			else
				inttm_d -= 3; // for feb non leap year
		}
	}

	/* month overflow | correct year */
	if(inttm_mo < 0) {
		inttm_mo += 12;
		inttm_y -= 1;
	}

	string strtm_y = to_string(inttm_y);
	string strtm_mo = to_string(inttm_mo);
	string strtm_d = to_string(inttm_d);
	string strtm_h = to_string(inttm_h);
	string strtm_mn = to_string(ptm->tm_min);
	string strtm_s = to_string(ptm->tm_sec);

	
	return strtm_y + "-" + strtm_mo + "-" + strtm_d + " " + strtm_h + ":" + strtm_mn + ":" + strtm_s;
}