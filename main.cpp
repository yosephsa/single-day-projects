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
int sqlitecb_expose(void *NotUsed, int argc, char **argv, char **azColName);
int sqlite_clearcb();
string seconds_to_datetime(struct tm * ptm);
int change_timezone(struct tm * ptm, int utc_offset);
int sqlite_insert(string table, int datasize, int direction);


/* --- GLOBAL VARIABLES --- */
string TABLE_NAME = "BW_MONITOR";
int sqlite_argc, sqlite_rc;
char **sqlite_argv, **sqlite_azColName, *sqlite_err;
sqlite3 *db;

/* --- GLOBAL FUNCTIONS --- */
int main(int argc, char *argv[])
{
	int rv, devNum = -1;
	
	if(argc == 2) {
		devNum = argv[0][0]-46;
	}

	rv = initSQLite("bwmonitor.db");
	if(rv != 0)
		return 1;

	rv = initNetworkListener(devNum);
	if(rv != 0)
		return 1;

	if(db != NULL)
		sqlite3_close(db);

	return(0);
}

int initSQLite(string s) {
	char *zErrMsg = 0;
	string sql;

	sqlite_rc = sqlite3_open(s.c_str(), &db);

	if( sqlite_rc ) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	} else {
		fprintf(stderr, "Opened database successfully\n");
	}

	/* CHECK IF TABLE EXISTS */
	sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + TABLE_NAME + "';";
	sqlite_clearcb();
	sqlite_rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &zErrMsg);

	/* CREATE TABLE */
	if(sqlite_argc == 0) { 
		sql = "CREATE TABLE " + TABLE_NAME + "("  \
			"DATA_SIZE            INTEGER     NOT NULL," \
			"DIRECTION            INTEGER     NOT NULL," \
			"TIME_STAMP        INTEGER);";

		/* Clear Output & Execute SQL statement */
		sqlite_clearcb();
		sqlite_rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &zErrMsg);
		
		if( sqlite_rc != SQLITE_OK ){
			fprintf(stderr, "Can't create table. SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
			return 2;
		} else {
			cout << "Table " + TABLE_NAME + " created successfully" << endl;
		}
	}
	
	return 0;
}

int sqlite_insert(string table, int datasize, int direction) {
	char *zErrMsg = 0;

	//STORE DATA IN SQL DB
	string sql = "INSERT INTO " + table + " (DATA_SIZE, DIRECTION, TIME_STAMP) " \
	"VALUES(" + to_string(datasize) + ", " + to_string(direction) + ", datetime('now'));";
	sqlite_clearcb();
	int sqlite_rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &sqlite_err);

	if( sqlite_rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s", zErrMsg);
		cout << " | QUERY: " << sql << endl;
		sqlite3_free(zErrMsg);
		return 1;
	} else {
		cout << "Insertion successfully" << endl;
		return 0;
	}
}



int sqlite_clearcb() {
	sqlite_argc = 0;
	sqlite_argv = NULL;
	sqlite_azColName = NULL;

	return 0;
}

int sqlitecb_expose(void *NotUsed, int argc, char **argv, char **azColName) {

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
	char *zErrMsg = 0;
	time_t rawtime = time(NULL);

	struct tm * ptm = gmtime(&rawtime);
	change_timezone(ptm, CDT);
	string datetime = seconds_to_datetime(ptm);

	cout << "Jacked packet | size is " << header->len << "bytes | datetime is (" 
		<< datetime << ") ";


	sqlite_insert(TABLE_NAME, header->len, 0);
}

/**
  *	Change timezone using utc_offset. parameter is manipulated and
  *	the change is made to the pointer.
  *
  * @param (struct tm)ptm 	in assumed to be in utc time. Will be
  *							different upon completion of fnct
  */
int change_timezone(struct tm * ptm, int utc_offset) {
	ptm->tm_year = ptm->tm_year;
	ptm->tm_mon = ptm->tm_mon;
	ptm->tm_mday;
	ptm->tm_hour = ptm->tm_hour+utc_offset;

	/* hour overflow | correct day */
	if(ptm->tm_hour < 0) {
		ptm->tm_hour += 24;
		ptm->tm_mday -= 1;
	}

	/* day overflow | correct month */
	if(ptm->tm_mday < 0) {
		ptm->tm_mday += 31;
		ptm->tm_mon -= 1;
		/* Correct days 31/30/28/29 */
		if(ptm->tm_mon == 3 || ptm->tm_mon == 5 || ptm->tm_mon == 8 || ptm->tm_mon == 10)
			ptm->tm_mday -= 1; // For months w/ 30 days
		if(ptm->tm_mon == 2) {
			if(ptm->tm_year%4 == 0) // for feb leap year
				ptm->tm_mday -= 2;
			else
				ptm->tm_mday -= 3; // for feb non leap year
		}
	}
	
	/* month overflow | correct year */
	if(ptm->tm_mon < 0) {
		ptm->tm_mon += 12;
		ptm->tm_year -= 1;
	}

	return 0;
}

/**
  *	Convert struct tm to string datetime
  *	datetime format is YYYY-MM-DD HH:MM:SS
  *
  * @param (struct tm)ptm
  * @return (string)datetime
  */
string seconds_to_datetime(struct tm * ptm) {
	string strtm_y = to_string(ptm->tm_year+1900);
	string strtm_mo = to_string(ptm->tm_mon+1);
	string strtm_d = to_string(ptm->tm_mday);
	string strtm_h = to_string(ptm->tm_hour);
	string strtm_mn = to_string(ptm->tm_min);
	string strtm_s = to_string(ptm->tm_sec);

	
	return strtm_y + "-" + strtm_mo + "-" + strtm_d + " " + strtm_h + ":" + strtm_mn + ":" + strtm_s;
}