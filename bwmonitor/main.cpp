#include <iostream>
#include <string>
#include <stdio.h>
#include <pcap.h>
#include <sqlite3.h>
#include <time.h>  
#include <vector> 
#include<cmath>

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
string seconds_to_datetime(struct tm * ptm);
int time_correct(struct tm * ptm, int utc_offset);
int sqlite_insert(string table, int datasize, int direction);
int send_report();
string zellersAlgorithm(int day, int month, int year);

/* --- GLOBAL VARIABLES --- */
string TABLE_NAME = "BW_MONITOR";
int sqlite_argc, sqlite_rc, pktlen_sum;
char *sqlite_err;
vector<string> sqlite_azColName;
vector<string> sqlite_argv;
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

	send_report();
	rv = initNetworkListener(devNum);
	if(rv != 0)
		return 1;

	while(1) {

	}

	if(db != NULL)
		sqlite3_close(db);

	return(0);
}



int run_sniffer(pcap_t* handle) {

	const u_char *packet;		/* The actual packet */
	struct pcap_pkthdr header;	/* The header that pcap gives us */

	while(1) {
		cout << endl;
		/* Loop packets */
		pktlen_sum = 0;
		pcap_loop(handle, 20000, got_packet, NULL);

		//Store
		sqlite_insert(TABLE_NAME, pktlen_sum, 0);

		//Output for debugging
		cout << "Jacked packets | size is " << pktlen_sum << " bytes." << endl;
	}
	return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	pktlen_sum += header->len;
}

/*********************************************************************************/
/* ****************************  INIT FUNCTIONS    ***************************** */
/*********************************************************************************/

/**
  * Initialize network listener. Set pcap and opon device
  * and start sniffing network.
  *
  * @param selectedDevNum the device to listen to. If -1 will auto choose.
  * @return execution result 	0 = success, 
  *								1 = can't open device, 
  *								2 = can't create filter, 
  *								3 = can't install filter).
  */
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
	
	//Open selected network device
	pcap_t *handle;
	handle = pcap_open_live(selectedDev->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", selectedDev, errbuf);
		return(1);
	}
	cout << "Opened device " << selectedDev->name << endl;


	/* === SNIFF ON DEVICE === */
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
		return(3);
	}
	
	run_sniffer(handle);

	/* And close the session */
	pcap_close(handle);
	return(0);
}

/**
  * Initialize SQLite DB. Open specified file and create table if one doesn't exist.
  *
  *	@param s the DB file name.
  * @return execution result. (0 = success, 1 = can't open file, 2 = can't create table).
  */
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
	sqlite_rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &zErrMsg);

	/* CREATE TABLE */
	if(sqlite_argc == 0) { 
		sql = "CREATE TABLE " + TABLE_NAME + "("  \
			"DATA_SIZE            INTEGER     NOT NULL," \
			"DIRECTION            INTEGER     NOT NULL," \
			"TIME_STAMP        INTEGER);";

		/* Clear Output & Execute SQL statement */
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

/*********************************************************************************/
/* ****************************  UTIL FUNCTIONS    ***************************** */
/*********************************************************************************/

int send_report() {
	int data_used[7];
	string du_sql[7];

	for(int i = 0; i < 7; i++) {
		//Initialize data_used
		data_used[i] = 0;

		//Create sql query
		if(i == 0)
			du_sql[i] = "SELECT SUM(DATA_SIZE) FROM " + TABLE_NAME + " WHERE TIME_STAMP > datetime('now', '-1 days'); ";
		else
			du_sql[i] = "SELECT SUM(DATA_SIZE) FROM " + TABLE_NAME + " WHERE TIME_STAMP < datetime('now', '-" + to_string(i) + " days') " \
												" AND TIME_STAMP > datetime('now', '-" + to_string(i+1) + " days'); ";
		
		//Submit sql query
		sqlite_rc = sqlite3_exec(db, du_sql[i].c_str(), sqlitecb_expose, 0, &sqlite_err);
		
		if( sqlite_rc != SQLITE_OK ){
			fprintf(stderr, "SQL error: %s", sqlite_err);
			cout << " | QUERY: " << du_sql[i] << endl;
			sqlite3_free(sqlite_err);
			data_used[i] = -1;
		} else {
			time_t rawtime = time(NULL);
			struct tm * ptm = gmtime(&rawtime);
			time_correct(ptm, 0);
			ptm->tm_mday -= i;
			string day = zellersAlgorithm(ptm->tm_mday, ptm->tm_mon+1, ptm->tm_year+1900);

			cout << day << ": " ;
			if(sqlite_argc > 0) {
				cout << "Data used is " << sqlite_argv.at(0) << "bytes";
			} else
				cout << "No data";
			cout << endl;

		}
	}
	
	// Submit SQL requests and store data
	for(int i = 0; i < 7;  i++) {
		
	}

	return 0;
	
}

int sqlite_insert(string table, int datasize, int direction) {
	char *zErrMsg = 0;

	//STORE DATA IN SQL DB
	string sql = "INSERT INTO " + table + " (DATA_SIZE, DIRECTION, TIME_STAMP) " \
	"VALUES(" + to_string(datasize) + ", " + to_string(direction) + ", datetime('now'));";
	sqlite_rc = sqlite3_exec(db, sql.c_str(), sqlitecb_expose, 0, &sqlite_err);

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

int sqlitecb_expose(void *NotUsed, int argc, char **argv, char **azColName) {

	//Erase values from global vars
	sqlite_argc = argc;
	sqlite_argv.clear();
	sqlite_azColName.clear();

	//Store values in global vars
	for(int i = 0; i<argc; i++) {
		try { /* Test if arg*/ 
			string val(argv[i]);
			sqlite_argv.push_back(val);
			
			string col(azColName[i]);
			sqlite_azColName.push_back(col);

		} catch (...) { 
			sqlite_argc = i; // Set the num of arguments to number of successful loops (i.e. index)
			continue;
		}
	}
	return 0;
}

/**
  *	Change timezone using utc_offset. parameter is manipulated and
  *	the change is made to the pointer. And correct under and over flow
  * of datetime
  *
  * @param (struct tm)ptm 	in assumed to be in utc time. Will be
  *							different upon completion of fnct
  */
int time_correct(struct tm * ptm, int utc_offset) {
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

string zellersAlgorithm(int day, int month, int year){
	string weekday[7] = {"Saturday","Sunday","Monday","Tuesday", "Wednesday","Thursday","Friday"};
	
	int mon;
	if(month > 2)
		mon = month; //for march to december month code is same as month
	else {
		mon = (12+month); //for Jan and Feb, month code will be 13 and 14 year--; //decrease year for month Jan and Feb
	}
	int y = year % 100; //last two digit
	int c = year / 100; //first two digit
	int w = (day + floor((13*(mon+1))/5) + y + floor(y/4) + floor(c/4) + (5*c));
	w = w % 7;
	return weekday[w];
}