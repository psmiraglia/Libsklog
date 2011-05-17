#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>

#include <sklog.h>

#define    NLOGS 7
#define    SK_DATABASE_PATH        "./logs.db"
#define     LARGE_BUFLEN        1024
#define     XSMALL_BUFLEN       128
#define     XLARGE_BUFLEN       2048


/* This is the key used to simulate the key exchange from T and U */
unsigned char thekey[SK_AUTH_KEY_LEN] = { 
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0xbb,0xcc,0xdd,0xee,0xff,0x0a,0x1b,0x2c,0x3d,0x4f,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0xdd,0xee
};

void print_le(SKLogEntry le)
{
    int i = 0;
    
    fprintf(stdout,"   TYPE: ");
    for ( i = 0 ; i < SK_LOGENTRY_TYPE_LEN ; i++ )
        fprintf(stdout,"%2.2x",le.type[i]);
    fprintf(stdout,"\n");

    fprintf(stdout,"   DATA ENC: ");
    for ( i = 0 ; i < le.data_enc_len ; i++ )
        fprintf(stdout,"%2.2x",le.data_enc[i]);
    fprintf(stdout,"\n");
    
    fprintf(stdout,"   HASH: ");
    for ( i = 0 ; i < SK_HASH_CHAIN_LEN ; i++ )
        fprintf(stdout,"%2.2x",le.hash[i]);
    fprintf(stdout,"\n");
    
    fprintf(stdout,"   HMAC: ");
    for ( i = 0 ; i < SK_HMAC_LEN ; i++ )
        fprintf(stdout,"%2.2x",le.hmac[i]);
    fprintf(stdout,"\n\n");
    
    fprintf(stdout,"   QUOTE: ");
    for ( i = 0 ; i < le.quote_size ; i++ )
        fprintf(stdout,"%2.2x",le.quote[i]);
    fprintf(stdout,"\n\n");
}   

int save2db(SKLogEntry le,sqlite3 *db)
{
    int ret = 0;
    unsigned int i = 0;
    unsigned int j = 0;

    char *zErrMsg = 0;
    const char *query_head = "insert into le (le_type,le_enc_data,le_hash_chain,le_hmac) values";

    char query[LARGE_BUFLEN] = { 0 };

    char le_type[XSMALL_BUFLEN] = { 0 };
    char le_enc_data[XLARGE_BUFLEN] = { 0 };
    char le_hash_chain[XSMALL_BUFLEN] = { 0 };
    char le_hmac[XSMALL_BUFLEN] = { 0 };

    for ( i=0 , j=0 ; i < SK_LOGENTRY_TYPE_LEN ; i++ , j+=2 )
        sprintf(&le_type[j],"%2.2x",le.type[i]);

    for ( i=0 , j=0 ; i < le.data_enc_len ; i++ , j+=2)
        sprintf(&le_enc_data[j],"%2.2x",le.data_enc[i]);

    for ( i=0 , j=0 ; i < SK_HASH_CHAIN_LEN ; i++ , j+=2 )
        sprintf(&le_hash_chain[j],"%2.2x",le.hash[i]);

    for ( i=0 , j=0 ; i < SK_HMAC_LEN ; i++ , j+=2 )
        sprintf(&le_hmac[j],"%2.2x",le.hmac[i]);
    
    sprintf(query,"%s ('%s','%s','%s','%s');",
            query_head,le_type,le_enc_data,le_hash_chain,le_hmac);

    /* exec query */
    ret = sqlite3_exec(db,query,NULL, 0, &zErrMsg);
    if ( ret != SQLITE_OK ) {
        fprintf(stderr, "ERR: SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    return SK_SUCCESS;
}

int main (void)
{
    char *logs[NLOGS] = {
        "Vivamus vulputate diam non purus vehicula faucibus.",
        "Pellentesque dignissim tellus ut ipsum semper in hendrerit augue gravida.",
        "Phasellus at lectus vitae nisl aliquet pretium eu congue enim.",
        "Quisque fringilla magna a ligula ornare vel tincidunt nulla dictum.",
        "Nullam non dui vel justo dictum condimentum eget eget urna.",
        "In pharetra consequat augue, fermentum interdum eros sodales eget.",
        "Mauris feugiat augue ut purus auctor aliquet."
    };
        
    SKCTX ctx;
    SKLogEntry le;
    
    int ret = 0;
    int i = 0,j = 0;
    sqlite3 *db = 0;
    
    unsigned char *blob = 0;
    unsigned int blob_len = 0;

    
    /* clear database */
    ret = sqlite3_open(SK_DATABASE_PATH,&db);

    if ( ret == SQLITE_OK ) { 
        ret = sqlite3_exec(db,"create table le (lekey INTEGER PRIMARY KEY,\
le_type TEXT,le_enc_data TEXT,le_hash_chain TEXT,le_hmac TEXT,tpm_quote TEXT)",0, 0, NULL);
        ret = sqlite3_exec(db,"delete from le",0, 0, NULL);
    }
    else {
        /* unable to open database */
        fprintf(stderr,"ERR: Can't open database\n");
        sqlite3_close(db);
        return SK_FAILURE;
    }

    /* initialize the Schneier-Kelsey context */
    SKLOG_InitCtx(&ctx);
    
    /* set the authentication key from wich start the auth_key generation */
    SKLOG_SetAuthKeyZero(&ctx,thekey);
    
    /* initialize the log entry */
    SKLOG_InitLogEntry(&le);
    
    /* generate the LogfileOpen logentry */
    //SKLOG_Open(&ctx,&le);
    SKLOG_Write(&ctx,NULL,0,LogfileInitialization,&le);
    
    save2db(le,db);
    print_le(le);
    
    for ( i = 0 ; i < NLOGS ; i++ ) {
        SKLOG_ResetLogEntry(&le);
        /* generate a generic log entry */
        SKLOG_Write(&ctx,logs[i],strlen(logs[i]),TYPE_ONE,&le);
        
        /* convert the log entry 'le' in a blob_len byte blob */
        //~ ret = SKLOG_LogEntryToBlob(&blob,&blob_len,&le);
        //~ 
        //~ if ( ret == SK_SUCCESS ) {
            //~ fprintf(stdout,"Blob: ");
            //~ for( j=0 ; j < blob_len ; j++ )
                //~ fprintf(stdout,"%2.2x",blob[j]);
            //~ fprintf(stdout,"\n");
            //~ free(blob);
        //~ }
        save2db(le,db);
        print_le(le);
    }
    
    SKLOG_ResetLogEntry(&le);
    
    /* generate the LogfileClosure logentry */
    SKLOG_Write(&ctx,NULL,0,LogfileClosure,&le);
    
    save2db(le,db);
    print_le(le);
    
    //~ SKLOG_ResetLogEntry(&le);
    
    sqlite3_close(db);
    
    return 0;
}
