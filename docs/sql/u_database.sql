/*-------------------------------------------------------------------*/
/*                    create tables for U component                  */
/*-------------------------------------------------------------------*/

drop table if exists LOGFILE;
drop table if exists LOGENTRY;

create table if not exists LOGFILE (
    f_id        INTEGER PRIMARY KEY,
    f_uuid      VARCHAR(36) NOT NULL,
    ts_start    VARCHAR(18) NOT NULL,
    ts_end      VARCHAR(18) NOT NULL
);

create table if not exists LOGENTRY (
    e_id        INTEGER PRIMARY KEY,
    f_id        INTEGER NOT NULL,
    e_type      INTEGER NOT NULL,
    e_data      VARCHAR(4096) NOT NULL,
    e_hash      VARCHAR(32) NOT NULL,
    e_hmac      VARCHAR(32) NOT NULL
);

