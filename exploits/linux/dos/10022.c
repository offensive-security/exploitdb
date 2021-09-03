int main(void)
{
	int ret;
	int csd;
	int lsd;
	struct sockaddr_un sun;

	/* make an abstruct name address (*) */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = PF_UNIX;
	sprintf(&sun.sun_path[1], "%d", getpid());

	/* create the listening socket and shutdown */
	lsd = socket(AF_UNIX, SOCK_STREAM, 0);
	bind(lsd, (struct sockaddr *)&sun, sizeof(sun));
	listen(lsd, 1);
	shutdown(lsd, SHUT_RDWR);

	/* connect loop */
	alarm(15); /* forcely exit the loop after 15 sec */
	for (;;) {
		csd = socket(AF_UNIX, SOCK_STREAM, 0);
		ret = connect(csd, (struct sockaddr *)&sun, sizeof(sun));
		if (-1 == ret) {
			perror("connect()");
			break;
		}
		puts("Connection OK");
	}
	return 0;
}