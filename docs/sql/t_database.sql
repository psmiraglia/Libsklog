/*-------------------------------------------------------------------*/
/*                    create tables for T component                  */
/*-------------------------------------------------------------------*/

drop table if exists AUTHKEY;
drop table if exists LOGFILE;
drop table if exists LOGENTRY;
drop table if exists M0MSG;

create table if not exists AUTHKEY (
    k_id        INTEGER PRIMARY KEY,
    u_ip        VARCHAR(17) NOT NULL,
    f_uuid      VARCHAR(36) NOT NULL,
    authkey     VARCHAR(32) NOT NULL
);

create table if not exists LOGENTRY (
    e_id        INTEGER PRIMARY KEY,
    f_uuid      VARCHAR(36) NOT NULL,
    e_type      INTEGER NOT NULL,
    e_data      VARCHAR(4096) NOT NULL,
    e_hash      VARCHAR(32) NOT NULL,
    e_hmac      VARCHAR(32) NOT NULL
);

create table if not exists M0MSG (
	m_id        INTEGER PRIMARY KEY,
	u_ip        VARCHAR(17) NOT NULL,
	f_uuid      VARCHAR(36) NOT NULL,
	m0_msg      VARCHAR(5120) NOT NULL
);

