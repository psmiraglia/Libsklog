// #include <time.h>
// #include <unistd.h>

#include <sklog_u.h>

#define MAX 1
#define LOGFILE_SIZE 30
#define LOGENTRY_LEN 1024

char logfile[300][LOGENTRY_LEN] = {
    "Etiam ut ornare lacinia arcu ultrices sit.",
    "Neque scelerisque volutpat, orci aptent nisi, ut tellus tincidunt senectus, taciti nostra urna.",
    "Dignissim tempus cum cubilia.",
    "Ligula dolor hymenaeos natoque.",
    "Sapien, ac magnis egestas.",
    "Consectetuer eu commodo mi, facilisi primis, nascetur parturient.",
    "Quam eu massa diam dapibus euismod pede.",
    "At sapien ac dolor.",
    "Velit fames semper libero.",
    "Dictum.",
    "Mauris porta bibendum per, conubia sagittis feugiat accumsan et elit.",
    "Eleifend parturient semper vel, mattis ultrices.",
    "Nulla orci velit, class nostra quis nisl lacus.",
    "Cum rutrum hymenaeos.",
    "Magnis vehicula, ullamcorper habitant iaculis eleifend dictum tortor erat.",
    "VM (instance-00000001.img) creation",
    "Natoque quis, mi leo consequat taciti rutrum lacus dis.",
    "Purus primis sem, inceptos elementum quis scelerisque vivamus dui.",
    "Diam volutpat non, tellus mus taciti, arcu condimentum aliquet fusce quis tempus.",
    "Congue.",
    "Tempor, et sit tincidunt platea a gravida tellus, semper nibh ullamcorper id, tempor rhoncus feugiat auctor pede et.",
    "Purus auctor in habitant nunc facilisi leo, euismod a, nullam fames.",
    "Proin ad hymenaeos pede, integer ipsum.",
    "Sociis odio, dignissim nostra.",
    "Nonummy id, justo.",
    "Ornare venenatis varius lacus pulvinar dignissim pellentesque adipiscing duis hymenaeos varius vestibulum.",
    "Fusce ac netus consectetuer.",
    "Integer, sollicitudin platea etiam eget.",
    "Quam curae luctus eget, mi tincidunt.",
    "Congue convallis platea metus hac.",
    "Ut, mus ut tempor eu.",
    "Sodales quam est mattis quisque, nonummy.",
    "Nulla velit nibh dis eget adipiscing mi, lobortis aptent.",
    "Sit eros vivamus at, vitae et urna lorem.",
    "Odio ut duis interdum auctor.",
    "Tincidunt.",
    "Mi curabitur a, curabitur.",
    "Feugiat commodo dictum eni vestibulum mi, pharetra vehicula, at risus ac cras, lacus torquent.",
    "Non, ad class cras a nibh vestibulum mauris, quam consectetuer.",
    "Ac lacus maecenas massa placerat cum, laoreet a, mauris elit, mi porttitor.",
    "Donec nisi hac taciti augue hac nibh per fusce curabitur adipiscing eget.",
    "Nibh amet fusce quisque facilisis hac lacinia.",
    "Urna, amet purus id vitae.",
    "Risus netus vitae pretium dis, lobortis a, consectetuer ante.",
    "Velit hendrerit.",
    "Lacinia phasellus ut nibh pulvinar parturient litora ad mollis dolor vestibulum.",
    "Praesent, fermentum pellentesque.",
    "Pellentesque egestas lorem ad turpis.",
    "Leo.",
    "Cursus ad accumsan vivamus ac nec et dolor platea ullamcorper dolor dictum velit.",
    "Cum est blandit ac, odio vitae tempor.",
    "Pellentesque amet egestas.",
    "Lacinia odio, morbi neque vehicula amet interdum curae vivamus fusce eget.",
    "Class sociis ipsum viverra, ornare, nec.",
    "Quam, leo molestie elementum arcu fermentum mi, tristique diam, conubia a, ullamcorper est.",
    "Eget eu.",
    "Nisi ligula nonummy odio.",
    "At porta primis molestie euismod.",
    "Pede tortor nostra.",
    "Urna elit dignissim varius.",
    "At ad facilisis netus urna sem leo.",
    "Ve ante mauris pretium.",
    "Cum elit velit mauris fames odio nibh fusce fames per.",
    "Commodo lacus.",
    "Quam vestibulum.",
    "Suspendisse cras, quam, ad justo lectus ipsum enim, rutrum nullam, suscipit.",
    "Facilisis luctus morbi nec duis.",
    "Eros montes potenti.",
    "Cras habitant nam, cubilia a, suspendisse nec, id pellentesque commodo morbi justo magnis suscipit per tempus nonummy aliquam.",
    "Ve metus eleifend adipiscing potenti per parturient.",
    "Felis vestibulum torquent massa a aliquet tempus, felis adipiscing.",
    "Ante feugiat lacus lorem.",
    "Mollis laoreet enim urna ipsum mi dis venenatis lorem proin.",
    "Dis eu sollicitudin posuere, duis nec quis non vitae cum cum.",
    "Faucibus eni, fusce semper ut faucibus nam, litora.",
    "Vitae sem erat nostra sed.",
    "Leo tincidunt praesent, amet conubia felis ante ultricies tortor, neque vitae taciti sollicitudin.",
    "Penatibus suspendisse porta primis ipsum, nec semper potenti, nibh eu pede euismod ante, eu magna.",
    "Commodo hendrerit elit varius quam, ad per tempus.",
    "Etiam diam per semper orci scelerisque laoreet netus dolor.",
    "Amet sodales a, scelerisque non, diam.",
    "Amet mollis potenti rhoncus aptent nunc eu tellus dui, dictum, cum nisi.",
    "Felis mi cras lectus.",
    "Vivamus aliquet phasellus erat amet.",
    "Etiam eu a sociis orci sodales.",
    "Adipiscing.",
    "Class fusce laoreet.",
    "Aptent fermentum nulla phasellus.",
    "Ipsum elementum cubilia porta per donec arcu.",
    "Mauris a conubia ad mus et elit aliquam erat, eros urna.",
    "Rutrum class, vestibulum orci ipsum id non ante.",
    "Ante adipiscing libero, mi phasellus a, lorem gravida magnis eu.",
    "Aliquet.",
    "Quam nisl fusce at nulla.",
    "Sollicitudin ornare.",
    "Nam at porta dolor risus class potenti.",
    "Duis sollicitudin.",
    "Fringilla accumsan velit tristique.",
    "Volutpat integer at cum consequat primis cursus.",
    "Eget, condimentum euismod suspendisse quis.",
    "Enim, pede eget.",
    "Sollicitudin tellus ad leo auctor eu, erat.",
    "Gravida ante fusce torquent, neque, ad, dignissim a.",
    "Erat, non odio dui class.",
    "Erat placerat metus congue tincidunt blandit massa quam pretium.",
    "Donec, commodo mi, in magnis nulla magna placerat.",
    "Dignissim, sollicitudin parturient diam.",
    "Tincidunt ac.",
    "Mi condimentum ut, ligula erat, nibh adipiscing libero ut semper sagittis.",
    "Turpis donec, ad metus dictumst facilisis ac, magna metus maecenas lacus euismod ante ultrices mattis, molestie.",
    "Cras sociosqu proin dui sociosqu vulputate rutrum lorem class.",
    "Vestibulum pellentesque natoque, curae vestibulum accumsan eros vivamus pede, magna euismod.",
    "Metus eni odio odio erat egestas donec parturient sagittis.",
    "Ullamcorper ultrices pede aenean ligula nascetur ad ornare pellentesque curabitur mauris adipiscing torquent.",
    "Odio id dolor dignissim adipiscing nisl sociis.",
    "Pretium.",
    "Tincidunt purus lacus ullamcorper mus, mollis facilisis mi, eros sagittis placerat donec.",
    "Consectetuer varius etiam penatibus lacus et ultricies.",
    "Porta metus velit dui parturient magna aliquet quam, vulputate.",
    "Maecenas sed, nulla etiam, morbi.",
    "Felis, eni hymenaeos.",
    "Nisi quam at.",
    "Egestas viverra sapien dis vestibulum parturient eu malesuada vitae elementum donec.",
    "Quis ve lacus libero magna.",
    "Ante porta quam nunc nisi.",
    "Augue torquent mus, quisque urna, a amet neque.",
    "Fusce netus, luctus magna, hendrerit pede.",
    "Fames.",
    "Aliquam.",
    "Amet ante orci lorem pretium inceptos dapibus.",
    "Risus, sed pulvinar commodo enim in.",
    "Arcu enim nonummy ve, viverra amet, lobortis.",
    "Hymenaeos bibendum vitae vel justo vitae, arcu id fames suspendisse ultrices dapibus justo quis.",
    "Etiam aptent nonummy commodo tellus nullam vel pretium varius eni orci.",
    "Velit.",
    "Tristique consectetuer.",
    "Blandit fusce ut ligula ac suscipit aliquet lacinia dignissim libero ipsum sagittis.",
    "Eleifend justo mi class et elementum eros, sed arcu sodales nibh, neque augue.",
    "Posuere fames at.",
    "Laoreet conubia aenean quam ut magna suscipit adipiscing.",
    "Aptent sodales sodales arcu nisl mauris.",
    "Ac ridiculus parturient, commodo erat id diam dignissim auctor, inceptos condimentum nascetur, convallis pellentesque adipiscing cras habitasse.",
    "Euismod ante ad.",
    "Tellus enim fermentum mi, fusce ullamcorper in congue.",
    "Semper suspendisse neque tempus platea nisl.",
    "Inceptos.",
    "Cras nonummy.",
    "A purus ac auctor phasellus donec magnis congue.",
    "Placerat volutpat egestas nullam pede ad faucibus.",
    "Cras, a elit eu fusce at curabitur a.",
    "Dui adipiscing class.",
    "Ac mauris posuere ad cursus vulputate vestibulum nisi tempus conubia ac.",
    "Tellus mollis justo scelerisque accumsan, vivamus pretium elementum duis feugiat at, diam.",
    "Vehicula lorem eget tellus, ac.",
    "Dapibus lorem nisl ac elit lorem ad.",
    "Fames amet aenean.",
    "Nulla netus taciti sociis eros curabitur.",
    "Varius.",
    "Nisi tristique accumsan.",
    "Nisi.",
    "Nibh ultricies suscipit.",
    "Turpis, mollis curae.",
    "Porttitor at, justo orci ac phasellus integer.",
    "Primis est nisi fames et tincidunt risus erat eni sit.",
    "Elementum montes, massa et netus augue montes felis integer.",
    "Magnis a, quisque ad nisi.",
    "Sed nunc commodo ad, cum enim ornare fringilla velit pharetra velit eu ornare.",
    "Ultricies non lacus libero fusce.",
    "Risus.",
    "Sed, nostra, tincidunt parturient enim lorem eu mattis penatibus posuere.",
    "Montes molestie elit, phasellus.",
    "Porta purus, mauris risus, porta scelerisque sociosqu, orci.",
    "Urna elementum tempor accumsan consequat sagittis mauris litora praesent dignissim pharetra nostra nisl.",
    "Semper magna nam senectus.",
    "Nam cras, in rutrum egestas vivamus.",
    "Erat, eget duis lobortis.",
    "Lacinia magnis odio platea ac interdum.",
    "Ante posuere mi, et duis nisi parturient vel risus habitasse tortor imperdiet lectus interdum.",
    "A orci ve nisi viverra id, justo at aptent.",
    "Velit, curabitur phasellus nulla libero id montes non.",
    "Bibendum odio mus imperdiet aliquet, nec interdum.",
    "Nulla a pede ipsum massa, est hac ad.",
    "Nisi a orci mi nullam nulla mus enim, urna taciti, mattis, nam dapibus.",
    "Primis.",
    "Maecenas nibh quis penatibus id, porttitor nulla.",
    "Dapibus odio, dui nisi tortor sagittis elementum.",
    "Imperdiet hendrerit augue tincidunt quam.",
    "Varius vulputate in, elementum nisi, sem justo cubilia.",
    "Semper accumsan euismod lacinia porttitor eros aliquam tristique at.",
    "Dictum.",
    "Rutrum.",
    "Nunc potenti libero pede ridiculus turpis vehicula vestibulum turpis mi suscipit donec.",
    "Nunc et varius.",
    "Dictum placerat mattis semper magna pulvinar parturient ornare velit est adipiscing.",
    "Vestibulum quis sociis dignissim neque malesuada vestibulum.",
    "Varius.",
    "Quisque blandit ultrices mi nulla arcu odio id donec eni dolor.",
    "Rutrum fringilla massa a commodo ac.",
    "Vitae nunc a eros parturient orci curae augue tempor cras.",
    "Massa eu vulputate mi, tristique enim, potenti etiam cras.",
    "Quis lorem venenatis nisl commodo ut, id nisl dolor turpis neque taciti lorem metus.",
    "Lacinia, curae arcu non nisl pellentesque adipiscing pede metus aliquam.",
    "Turpis maecenas ultricies sollicitudin vestibulum.",
    "Consectetuer gravida vulputate sagittis erat orci.",
    "Proin aenean eu eros sagittis platea, erat elementum ut curabitur pretium, fames nulla neque.",
    "Pellentesque primis magna commodo dis, nullam.",
    "Nostra quisque, egestas ante augue potenti habitant.",
    "Parturient imperdiet, scelerisque curabitur enim nibh arcu nisl morbi nullam facilisi.",
    "Cursus eros, curae urna bibendum scelerisque, eni.",
    "Nisl lectus habitasse mi, magna fringilla eget.",
    "Phasellus nascetur class tristique nascetur.",
    "Ve, orci risus dapibus maecenas ve suspendisse nisi, odio per diam adipiscing hendrerit massa posuere.",
    "Dolor et lectus.",
    "Massa adipiscing vivamus eni id pellentesque.",
    "Diam morbi id.",
    "Sapien elementum faucibus.",
    "Vivamus porta.",
    "Cubilia.",
    "Non venenatis ipsum id lacus tempor lobortis sed iaculis ultrices donec.",
    "Cras non porta.",
    "Dictum ve lobortis per, amet.",
    "Ut lorem congue.",
    "Nibh quis curabitur.",
    "Nisi cum nisi.",
    "Et vehicula.",
    "Eros porta convallis per purus venenatis hymenaeos.",
    "Nam quisque mi, primis dolor dignissim enim aliquet neque.",
    "Justo lobortis tincidunt mollis justo rutrum tempus dis, elit.",
    "Maecenas phasellus consectetuer parturient eget auctor at lectus eleifend adipiscing dapibus orci parturient diam.",
    "Sodales nisl, sagittis adipiscing sociis augue proin.",
    "Adipiscing vestibulum eu turpis consectetuer pretium dui ut nostra.",
    "Cras gravida posuere posuere felis in.",
    "Sollicitudin urna dapibus dignissim elit dis.",
    "Nec penatibus velit quam aptent mi orci ad sollicitudin mauris, at nisl lectus cubilia ligula at eleifend.",
    "Felis ve varius inceptos dictum varius.",
    "Lectus sagittis aptent orci posuere et, nisi nibh fusce elementum nibh quis enim lorem cubilia.",
    "Vitae.",
    "Ad, tellus vitae.",
    "Class.",
    "Porttitor morbi fusce natoque dictum ante orci felis mattis curae amet, hymenaeos aptent.",
    "Viverra pede, a diam purus mi penatibus parturient, nibh mattis ante, condimentum in, cursus pulvinar imperdiet.",
    "Nisi felis lacinia sapien, est nullam penatibus.",
    "Suscipit tellus viverra eros et consectetuer cubilia, curae feugiat.",
    "Elementum iaculis nostra nec enim pellentesque interdum.",
    "Ve augue in eget fusce.",
    "Adipiscing fusce ante fames.",
    "Senectus parturient consequat lorem ornare nibh.",
    "Habitasse mi, aenean molestie morbi accumsan.",
    "Amet parturient nunc.",
    "Dui posuere sit, vestibulum metus amet, interdum massa.",
    "Quam eros eros orci.",
    "Sodales fames vel odio, et pulvinar donec aliquam molestie eu condimentum.",
    "Scelerisque ut, taciti sem, in neque velit primis.",
    "Lacinia rhoncus elit eu accumsan sodales aliquam mattis non dui sed facilisis.",
    "Duis tincidunt pellentesque parturient urna proin ultricies eni, per ut natoque cras, eu.",
    "Dapibus massa ipsum erat maecenas condimentum, maecenas.",
    "Congue id, justo scelerisque orci ligula, erat, enim.",
    "A, libero lorem risus eni.",
    "Netus eni vestibulum adipiscing et.",
    "Amet imperdiet lorem, nibh dictumst bibendum dapibus.",
    "Nam dictumst hymenaeos class eu ad nisl lacinia.",
    "Ipsum dis primis a, blandit eu sagittis.",
    "Orci.",
    "Eget aenean tempus viverra, nisl diam purus.",
    "Quam facilisis.",
    "Sapien enim sodales augue vitae a, conubia.",
    "Mi, ante sagittis litora, dictum dui parturient etiam.",
    "Iaculis, natoque fringilla mus amet vehicula sed.",
    "Quis posuere at, taciti nam pretium pulvinar urna.",
    "Quam consectetuer ad integer quam, rutrum sociosqu fames ve tellus et, vel ultricies magna.",
    "Fusce, netus auctor.",
    "Vivamus montes, augue.",
    "Curae amet elit morbi natoque hymenaeos, cursus a suscipit ante.",
    "Tristique tempor, lobortis quis, litora dignissim felis.",
    "Tempus donec dignissim torquent cras.",
    "Nisi conubia class hac risus nec.",
    "Enim donec vulputate egestas nibh lobortis ullamcorper, inceptos cras leo.",
    "Id augue quis mauris, et est facilisis.",
    "Bibendum fermentum erat velit.",
    "Porta ve arcu sociosqu nostra, tellus.",
    "Congue est quam ante sem.",
    "Ultricies morbi, feugiat, pharetra ut.",
    "Sem, turpis curabitur justo est pede curae erat dapibus nisl, dignissim.",
    "At.",
    "Consequat diam sapien in.",
    "Felis fringilla feugiat dictum cum.",
    "Duis turpis lacinia.",
    "Nisi neque aliquet dictum, hac ve facilisis fames conubia, bibendum mattis.",
    "Sollicitudin adipiscing ante ligula potenti potenti eget at lacus ut velit sapien.",
    "Conubia eros malesuada mus erat lobortis.",
    "Scelerisque et, sapien enim, ornare et tortor a, parturient non, porta nibh cubilia ut.",
    "Habitant quis molestie natoque, torquent.",
    "Eros.",
    "Cras quis fusce tortor lobortis in ullamcorper.",
    "Orci.",
    "Velit nulla mus nam et purus nisi egestas.",
    "Ad, condimentum odio, imperdiet vehicula, ligula nisl ut urna lacus est.",
    "Penatibus montes facilisi nisl lacinia iaculis convallis odio mus potenti donec ac a aenean facilisis.",
    "Hac eget suscipit enim, integer mi.",
    "Nec, enim accumsan pellentesque, magnis nulla non ante."
};

int main (void) {

    SKLOG_RETURN rv = 0;
    int index = 0;

    char *le1 = 0;
    unsigned int le1_len = 0;
    
    char *le2 = 0;
    unsigned int le2_len = 0;
    
    unsigned char *m0 = 0;
    unsigned int m0_len = 0;
    
    unsigned char *m1 = 0;
    unsigned int m1_len = 0;
    
    char *logs[BUF_512] = { 0x0 };
    unsigned int logs_size = 0;

    SKLOG_U_Ctx *u_ctx = 0;
    
    SKLOG_CONNECTION *c = 0;


init_logging_session:
    
    /* initialize context */
    
    u_ctx = SKLOG_U_NewCtx();
    
    if ( u_ctx == NULL ) {
		ERROR("SKLOG_U_NewCtx() failure");
		return 1;
	}
    
    rv = SKLOG_U_InitCtx(u_ctx);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_InitCtx() failure");
		return 1;
	}


	
	/*
	 *  initialize logging session phase
	 *
	 */

	
	rv = SKLOG_U_Open_M0(u_ctx, &m0, &m0_len, &le1, &le1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_M0() failure");
		return 1;
	}
    
    /* setup connection */
	
	c = SKLOG_CONNECTION_New();
	
	if ( c == NULL ) {
		ERROR("SKLOG_CONNECTION_New() failure");
		rv = SKLOG_FAILURE;
		goto error;
	}
	
	rv = SKLOG_CONNECTION_Init(c, u_ctx->t_address, u_ctx->t_port,
		u_ctx->u_cert, u_ctx->u_privkey, 0, 0);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Init() failure");
		goto error;
	}
	
	/* send m0 message */
	
	rv = send_m0(c, m0, m0_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("send_m0() failure");
		goto error;
	}
	
	/* waiting for m1 message */
	
	rv = receive_m1(c, &m1, &m1_len);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("receive_m1() failure");
		goto error;
	}
	
	/* free connection */
	
	rv = SKLOG_CONNECTION_Free(&c);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_CONNECTION_Free() failure");
		goto error;
	}
	
	rv = SKLOG_U_Open_M1(u_ctx, m1, m1_len, &le2, &le2_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_M1() failure");
		return 1;
	}
	
	/*
	 *  start logging
	 *
	 */
	
	
	while ( index < LOGFILE_SIZE ) {
		
		/* create log entry */
		
		rv = SKLOG_U_LogEvent(u_ctx, Undefined, logfile[1],
			strlen(logfile[1]), &le1, &le1_len);
		
		if ( rv == SKLOG_SESSION_TO_RENEW ) {
			
			SKLOG_U_FlushLogfile(u_ctx, logs, &logs_size);
			
			SKLOG_U_Close(u_ctx, &le1, &le1_len);
			SKLOG_U_FreeCtx(&u_ctx);
			goto init_logging_session;
		}
		
		index++;
	}
	
	/*
	 *  end application
	 *
	 */

    SKLOG_U_Close(u_ctx, &le1, &le1_len);
    SKLOG_U_FreeCtx(&u_ctx);
        
    return 0;
    
error:
	return 1;
}
