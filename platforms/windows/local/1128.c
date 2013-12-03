/*
  Will be moved to tools section shortly /str0ke

  Name: Windows Genuine Advantage Validation Patch
  Copyright: NeoSecurityTeam
  Author: HaCkZaTaN <hck_zatan@hotmail.com>
  Date: 31/07/05 21:42
  Description: LegitCheckControl.dll (1.3.254.0) 
  
 кФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФП
 Гўў                   -==[N]eo [S]ecurity [T]eam Inc.==-                   ўўГ
 РФТФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФТФй
 ГАГ     TiTLE : Windows Genuine Advantage Validation                       ГАГ  ГАУФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФДАГ
 ГАГ    AUTHOR : HaCkZaTaN                                                  ГАГ  кФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФП
 Гўў                           -==Information==-                            ўўГ  РФТФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФТФй
 ГАГ                                                                        ГАГ  ГАГ LegitCheckControl.dll (1.3.254.0)                                      ГАГ  ГАГ                                                                        ГАГ
 кФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФП
 Гўў                           -==Contact==-                                ўўГ
 РФТФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФТФй
 ГАГ                                                                        ГАГ
 ГАГ   [N]eo [S]ecurity [T]eam [NST]Ў - http://www.neosecurityteam.net/     ГАГ
 ГАГ   HaCkZaTaN <hck_zatan@hotmail.com>                                    ГАГ
 ГАГ   Irc.GigaChat.Net #uruguay                                            ГАГ
 ГАГ                                                                        ГАГ
 кФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФП
 Гўў                              -==Greets==-                              ўўГ
 РФТФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФТФй
 ГАГ                                                                        ГАГ
 ГАГ                            NST's Staff                                 ГАГ
 ГАГ                            erg0t                                       ГАГ
 ГАГ                            ][GB][                                      ГАГ
 ГАГ                            Beford                                      ГАГ
 ГАГ                            LINUX                                       ГАГ
 ГАГ                            Heap                                        ГАГ
 ГАГ                            CrashCool                                   ГАГ
 ГАГ                            Makoki                                      ГАГ
 ГАГ                            And my Colombian people                     ГАГ
 ГАГ                                                                        ГАГ  кФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФСФП
 Гўў                   -==[N]eo [S]ecurity [T]eam Inc.==-                   ўўГ
 РФТФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФФТФй
                          лллл   лллл ллллллллл ллллллллллл
                           ллллл  лл  ллл       лл  ллл  лл
                           лл лллллл  ллллллллл     ллл
                           лл   лллл        ллл     ллл
                          лллл    ллл ллллллллл    ллллл

*/

#include <stdio.h>

typedef struct bytepair BYTEPAIR;

struct bytepair
{
       long offset;
       char val;
}; 

static const BYTEPAIR byte_pairs[3]= { 
{0x2BE98, 0x33},
{0x2BE99, 0xC0},
{0x2BE9A, 0x90},
};

int main(int argc, char *argv[])
{
    FILE *LegitCheckControl;
    int i;

    printf("\n\tББББББББББББББББББББББББББББББББББББББББББББББББББББББББББББм\n"
           "\tБлпппппппппппппппппппппппппппппппппппппппппппппппппппппппппБл\n"
           "\tБл                                                         Бл\n"
           "\tБл           [N]eo [S]ecurity [T]eam [N][S][T]             Бл\n"
           "\tБл      [Windows Genuine Advantage Validation Patch]       Бл\n"
           "\tБл             LegitCheckControl.dll (1.3.254.0)           Бл\n"
           "\tБл                                                         Бл\n"
           "\tБл ллллллл   ллллллл   лллл   лл лл лллл  лллллллллллллллл Бл\n"
           "\tБл ллл  лллл  лл  лл   ллл   лл ллл  ллл  ллл лл лл лл ллл Бл\n"
           "\tБл ллл  л ллл лл  лл   ллл   лл      ллл  ллл    лл    ллл Бл\n"
           "\tБл ллл  л ллл лл  лл   ллл   лллл    ллл  ллл    лл    ллл Бл\n"
           "\tБл ллл  л   лллл  лл   ллл    ллллл  ллл  ллл    лл    ллл Бл\n"
           "\tБл ллл  л    ллл  лл   ллл      ллл  ллл  ллл    лл    ллл Бл\n"
           "\tБл ллл  л    ллл  лл   ллл   лл ллл  ллл  ллл    лл    ллл Бл\n"
           "\tБл ллл ллл    лл  лл   ллл   л лл    ллл  ллл   лллл   ллл Бл\n"
           "\tБл ллл            лл   ллл           ллл  ллл          ллл Бл\n"
           "\tБл лллл          ллл   лллл         лллл  лллл        лллл Бл\n"
           "\tБл                                                         Бл\n"
           "\tБл                 [ HaCkZaTaN  ..... ]                    Бл\n"
           "\tБл                 [ Paisterist ..... ]                    Бл\n"
           "\tБл                 [ Daemon21   ..... ]                    Бл\n"
           "\tБл                 [ g30rg3_x   ..... ]                    Бл\n"
           "\tБл            [ Http://WwW.NeoSecurityTeam.Net ]           Бл\n"
           "\tБл                                                         Бл\n"
           "\tББББББББББББББББББББББББББББББББББББББББББББББББББББББББББББл\n"
           "\t пппппппппппппппппппппппппппппппппппппппппппппппппппппппппппп\n\n\n");
           
           getchar();
           LegitCheckControl = fopen("LegitCheckControl.dll", "r+");
           
           if (LegitCheckControl == (FILE *)0)
           {
                       printf("LegitCheckControl.dll not found. Aborting.\n\n");
                       printf("Hit <Enter> to quit.");
                       getchar();
                       return 1;
           }
           
           printf("Starting...\n");
           
           for (i = 0; i < 3; i++)
           {
               fseek(LegitCheckControl, byte_pairs[i].offset, SEEK_SET);
               fwrite(&byte_pairs[i].val, 1, 1, LegitCheckControl);
           }
           
           fclose(LegitCheckControl);
           printf("->Patch completed.\n\n");
           printf("Done, enjoy...\n\n");
           getchar();

           return 0;
}

// milw0rm.com [2005-08-01]
