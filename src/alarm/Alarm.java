package alarm;


import CommonMethod.CommonUtil;
import CommonMethod.osSelect;
import NetSDKDemo.HCNetSDK;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.org.apache.bcel.internal.classfile.ConstantString;
import jdk.nashorn.internal.ir.debug.ClassHistogramElement;

import java.util.Scanner;


public class Alarm {
    static final String ALARM_IP = CommonUtil.getProperty("ALARM_IP");
    static final String ALARM_PORT = CommonUtil.getProperty("ALARM_PORT");
    static final String ALARM_MASK = CommonUtil.getProperty("ALARM_MASK");
    static final String ALARM_GATEWAY = CommonUtil.getProperty("ALARM_GATEWAY");
    static final String ALARM_DNS1 = CommonUtil.getProperty("ALARM_DNS1");
    static final String ALARM_DNS2 = CommonUtil.getProperty("ALARM_DNS2");


    // static final String DEVICE_USERNAME = CommonUtil.getProperty("DEVICE_USERNAME");
    // static final String DEVICE_PASSWORD = CommonUtil.getProperty("DEVICE_PASSWORD");
    // static final String DEVICE_IP = CommonUtil.getProperty("DEVICE_IP");
    // static final String DEVICE_PORT = CommonUtil.getProperty("DEVICE_PORT");
    static HCNetSDK hCNetSDK = null;
    static int lUserID = -1;// 用户句柄 实现对设备登录

    /**
     * 动态库加载
     *
     * @return
     */
    private static boolean createSDKInstance() {
        if (hCNetSDK == null) {
            synchronized (HCNetSDK.class) {
                String strDllPath = "";
                try {
                    if (osSelect.isWindows())
                        // win系统加载库路径
                        strDllPath = System.getProperty("user.dir") + "\\lib\\HCNetSDK.dll";
                    else if (osSelect.isLinux())
                        // Linux系统加载库路径
                        strDllPath = System.getProperty("user.dir") + "/lib/libhcnetsdk.so";
                    hCNetSDK = (HCNetSDK) Native.loadLibrary(strDllPath, HCNetSDK.class);
                } catch (Exception ex) {
                    System.out.println("loadLibrary: " + strDllPath + " Error: " + ex.getMessage());
                    return false;
                }
            }
        }
        return true;
    }


    /**
     * @param args
     */
    public static void main(String[] args) throws InterruptedException {

        // 配置文件参数校验
        if (!checkConfig()) {
            System.err.println("配置文件参数校验失败");
            return;
        }


        if (hCNetSDK == null) {
            if (!createSDKInstance()) {
                System.out.println("Load SDK fail");
                return;
            }
        }
        // linux系统建议调用以下接口加载组件库
        if (osSelect.isLinux()) {
            HCNetSDK.BYTE_ARRAY ptrByteArray1 = new HCNetSDK.BYTE_ARRAY(256);
            HCNetSDK.BYTE_ARRAY ptrByteArray2 = new HCNetSDK.BYTE_ARRAY(256);
            // 这里是库的绝对路径，请根据实际情况修改，注意改路径必须有访问权限
            String strPath1 = System.getProperty("user.dir") + "/lib/libcrypto.so.1.1";
            String strPath2 = System.getProperty("user.dir") + "/lib/libssl.so.1.1";

            System.arraycopy(strPath1.getBytes(), 0, ptrByteArray1.byValue, 0, strPath1.length());
            ptrByteArray1.write();
            hCNetSDK.NET_DVR_SetSDKInitCfg(3, ptrByteArray1.getPointer());

            System.arraycopy(strPath2.getBytes(), 0, ptrByteArray2.byValue, 0, strPath2.length());
            ptrByteArray2.write();
            hCNetSDK.NET_DVR_SetSDKInitCfg(4, ptrByteArray2.getPointer());

            String strPathCom = System.getProperty("user.dir") + "/lib/";
            HCNetSDK.NET_DVR_LOCAL_SDK_PATH struComPath = new HCNetSDK.NET_DVR_LOCAL_SDK_PATH();
            System.arraycopy(strPathCom.getBytes(), 0, struComPath.sPath, 0, strPathCom.length());
            struComPath.write();
            hCNetSDK.NET_DVR_SetSDKInitCfg(2, struComPath.getPointer());
        }

        /**初始化*/
        hCNetSDK.NET_DVR_Init();
        /** 设备上传的报警信息是COMM_VCA_ALARM(0x4993)类型，
         在SDK初始化之后增加调用NET_DVR_SetSDKLocalCfg(enumType为NET_DVR_LOCAL_CFG_TYPE_GENERAL)设置通用参数NET_DVR_LOCAL_GENERAL_CFG的byAlarmJsonPictureSeparate为1，
         将Json数据和图片数据分离上传，这样设置之后，报警布防回调函数里面接收到的报警信息类型为COMM_ISAPI_ALARM(0x6009)，
         报警信息结构体为NET_DVR_ALARM_ISAPI_INFO（与设备无关，SDK封装的数据结构），更便于解析。*/

        HCNetSDK.NET_DVR_LOCAL_GENERAL_CFG struNET_DVR_LOCAL_GENERAL_CFG = new HCNetSDK.NET_DVR_LOCAL_GENERAL_CFG();
        struNET_DVR_LOCAL_GENERAL_CFG.byAlarmJsonPictureSeparate = 1;   // 设置JSON透传报警数据和图片分离
        struNET_DVR_LOCAL_GENERAL_CFG.write();
        Pointer pStrNET_DVR_LOCAL_GENERAL_CFG = struNET_DVR_LOCAL_GENERAL_CFG.getPointer();
        hCNetSDK.NET_DVR_SetSDKLocalCfg(17, pStrNET_DVR_LOCAL_GENERAL_CFG);
        // 登录设备
        // Alarm.login_V40( "192.168.0.64", (short) 8000, "admin", "xmhz1234");
        while (true) {
            // 保持连接状态
            Scanner scanner = new Scanner(System.in);
            System.out.println("请输入要更新的设备IP地址:");
            String deviceIp = scanner.nextLine();
            System.out.println("请输入要更新的设备端口号:");
            String devicePort = scanner.nextLine();
            System.out.println("请输入要更新的设备用户名:");
            String deviceUsername = scanner.nextLine();
            System.out.println("请输入要更新的设备密码:");
            String devicePassword = scanner.nextLine();
            System.out.println("正在登录设备,请稍后...\n");

            if (!Alarm.login_V40(deviceIp, Short.parseShort(devicePort), deviceUsername, devicePassword)) {
                System.out.println("登录失败,请检查设备参数是否正确,按任意键重新输入,按0退出");
                String flag = scanner.nextLine();
                if ("0".equals(flag)) {
                    break;
                }
                continue;
            }
            System.out.println("输入clean清除此设备远程告警服务地址,按其他任意键继续更新");
            String flag = scanner.nextLine();
            if ("clean".equals(flag)) {
                Alarm.cleanAlarmHostParam();
                System.out.println("正在注销,请稍后...\n");
                Alarm.logout();
                System.out.println("按任意键继续更新,按0退出");
                flag = scanner.nextLine();
                if ("0".equals(flag)) {
                    break;
                }
                continue;
            }
            System.out.println("\n正在更新设备参数,请稍后...\n");
            Alarm.setAlarmHostParam(ALARM_IP, Short.parseShort(ALARM_PORT), ALARM_GATEWAY, ALARM_MASK, ALARM_DNS1, ALARM_DNS2);
            System.out.println("正在注销,请稍后...\n");
            Alarm.logout();
            System.out.println("按任意键继续更新,按0退出");
            flag = scanner.nextLine();
            if ("0".equals(flag)) {
                break;
            }
        }
        // 释放SDK
        hCNetSDK.NET_DVR_Cleanup();
        return;
    }

    private static boolean cleanAlarmHostParam() {
        try {
            HCNetSDK.NET_DVR_NETCFG_V30 net_dvr_netcfg_v30 = new HCNetSDK.NET_DVR_NETCFG_V30();
            net_dvr_netcfg_v30.write();
            Pointer lpOutBuffer = net_dvr_netcfg_v30.getPointer();
            IntByReference pBytesReturned = new IntByReference(0);
            boolean bRet = hCNetSDK.NET_DVR_GetDVRConfig(lUserID, HCNetSDK.NET_DVR_GET_NETCFG_V30, 0, lpOutBuffer, net_dvr_netcfg_v30.size(), pBytesReturned);
            if (bRet) {
                System.out.println("-------获取报警主机参数成功-------");
                net_dvr_netcfg_v30.read();
                System.out.println("【IP地址】：" + new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIP.sIpV4));
                String ip = "0.0.0.0";
                short port = 0;
                System.out.println("【报警管理主机】：" + new String(net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4) + "-->" + ip);
                System.out.println("【报警管理主机端口】：" + net_dvr_netcfg_v30.wAlarmHostIpPort + "-->" + port);
                net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4 = ip.getBytes();
                net_dvr_netcfg_v30.wAlarmHostIpPort = port;
                net_dvr_netcfg_v30.write();

                bRet = hCNetSDK.NET_DVR_SetDVRConfig(lUserID, HCNetSDK.NET_DVR_SET_NETCFG_V30, 0, lpOutBuffer, net_dvr_netcfg_v30.size());
                if (bRet) {
                    System.out.println("-------清除报警主机参数成功-------");
                    return true;
                } else {
                    System.out.println("-------清除报警主机参数失败-------");
                    return false;
                }
            } else {
                System.out.println("-------获取报警主机参数失败-------");
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean checkConfig() {
        // 设备登录信息不能为空
        // if (CommonUtil.isEmpty(DEVICE_IP) || CommonUtil.isEmpty(DEVICE_PORT) || CommonUtil.isEmpty(DEVICE_USERNAME) || CommonUtil.isEmpty(DEVICE_PASSWORD)) {
        //     System.out.println("设备登录信息:[DEVICE_IP],[DEVICE_PORT],[DEVICE_USERNAME],[DEVICE_PASSWORD]不能为空");
        //     return false;
        // }
        // 报警主机信息不能为空
        if (CommonUtil.isEmpty(ALARM_IP) || CommonUtil.isEmpty(ALARM_PORT)) {
            System.out.println("报警远程主机信息:[ALARM_IP],[ALARM_PORT]不能为空");
            return false;
        }
        return true;
    }


    /**
     * 设备登录V40 与V30功能一致
     *
     * @param ip   设备IP
     * @param port SDK端口，默认设备的8000端口
     * @param user 设备用户名
     * @param psw  设备密码
     */
    public static boolean login_V40(String ip, short port, String user, String psw) {
        // 注册
        HCNetSDK.NET_DVR_USER_LOGIN_INFO m_strLoginInfo = new HCNetSDK.NET_DVR_USER_LOGIN_INFO();// 设备登录信息
        HCNetSDK.NET_DVR_DEVICEINFO_V40 m_strDeviceInfo = new HCNetSDK.NET_DVR_DEVICEINFO_V40();// 设备信息

        String m_sDeviceIP = ip;// 设备ip地址
        m_strLoginInfo.sDeviceAddress = new byte[HCNetSDK.NET_DVR_DEV_ADDRESS_MAX_LEN];
        System.arraycopy(m_sDeviceIP.getBytes(), 0, m_strLoginInfo.sDeviceAddress, 0, m_sDeviceIP.length());

        String m_sUsername = user;// 设备用户名
        m_strLoginInfo.sUserName = new byte[HCNetSDK.NET_DVR_LOGIN_USERNAME_MAX_LEN];
        System.arraycopy(m_sUsername.getBytes(), 0, m_strLoginInfo.sUserName, 0, m_sUsername.length());

        String m_sPassword = psw;// 设备密码
        m_strLoginInfo.sPassword = new byte[HCNetSDK.NET_DVR_LOGIN_PASSWD_MAX_LEN];
        System.arraycopy(m_sPassword.getBytes(), 0, m_strLoginInfo.sPassword, 0, m_sPassword.length());

        m_strLoginInfo.wPort = port;
        m_strLoginInfo.bUseAsynLogin = false; // 是否异步登录：0- 否，1- 是
        m_strLoginInfo.byLoginMode = 0;  // ISAPI登录
        m_strLoginInfo.write();

        lUserID = hCNetSDK.NET_DVR_Login_V40(m_strLoginInfo, m_strDeviceInfo);
        if (lUserID == -1) {
            System.out.println("登录失败，错误码为" + hCNetSDK.NET_DVR_GetLastError() + "错误信息为" + hCNetSDK.NET_DVR_GetErrorMsg(new IntByReference(hCNetSDK.NET_DVR_GetLastError())));
            return false;
        } else {
            System.out.println(ip + ":设备登录成功！");
            return true;
        }
    }


    /**
     * 获取报警主机参数
     */
    public static void getAlarmHostParam() {
        HCNetSDK.NET_DVR_NETCFG_V30 net_dvr_netcfg_v30 = new HCNetSDK.NET_DVR_NETCFG_V30();
        net_dvr_netcfg_v30.write();
        Pointer lpOutBuffer = net_dvr_netcfg_v30.getPointer();
        IntByReference pBytesReturned = new IntByReference(0);
        boolean bRet = hCNetSDK.NET_DVR_GetDVRConfig(lUserID, HCNetSDK.NET_DVR_GET_NETCFG_V30, 0, lpOutBuffer, net_dvr_netcfg_v30.size(), pBytesReturned);
        if (bRet) {
            System.out.println("获取报警主机参数成功");
            net_dvr_netcfg_v30.read();
            System.out.println("IP地址：" + new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIP.sIpV4));
            System.out.println("报警管理主机：" + new String(net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4));
            System.out.println("报警管理主机端口：" + net_dvr_netcfg_v30.wAlarmHostIpPort);
            System.out.println("子网掩码：" + new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIPMask.sIpV4));
            System.out.println("网关：" + new String(net_dvr_netcfg_v30.struGatewayIpAddr.sIpV4));
            System.out.println("首选DNS服务器：" + new String(net_dvr_netcfg_v30.struDnsServer1IpAddr.sIpV4));
            System.out.println("备选DNS服务器：" + new String(net_dvr_netcfg_v30.struDnsServer2IpAddr.sIpV4));
            System.out.println("多播组地址：" + new String(net_dvr_netcfg_v30.struMulticastIpAddr.sIpV4));
        } else {
            System.out.println("获取报警主机参数失败");
        }
    }

    /**
     * 设置报警主机参数
     *
     * @param ip
     * @param port
     * @param gateway
     * @param mask    子网掩码
     * @param dns1
     * @param dns2
     * @return
     */
    public static boolean setAlarmHostParam(String ip, short port, String gateway, String mask, String dns1, String dns2) {
        try {
            HCNetSDK.NET_DVR_NETCFG_V30 net_dvr_netcfg_v30 = new HCNetSDK.NET_DVR_NETCFG_V30();
            net_dvr_netcfg_v30.write();
            Pointer lpOutBuffer = net_dvr_netcfg_v30.getPointer();
            IntByReference pBytesReturned = new IntByReference(0);
            boolean bRet = hCNetSDK.NET_DVR_GetDVRConfig(lUserID, HCNetSDK.NET_DVR_GET_NETCFG_V30, 0, lpOutBuffer, net_dvr_netcfg_v30.size(), pBytesReturned);
            if (bRet) {
                System.out.println("-------获取报警主机参数成功-------");
                net_dvr_netcfg_v30.read();

                // 如果入参为空，则不修改
                if (ip == null || ip.isEmpty()) {
                    ip = new String(net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4);
                }
                if (port == 0) {
                    port = net_dvr_netcfg_v30.wAlarmHostIpPort;
                }
                if (gateway == null || gateway.isEmpty()) {
                    gateway = new String(net_dvr_netcfg_v30.struGatewayIpAddr.sIpV4);
                }
                if (mask == null || mask.isEmpty()) {
                    mask = new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIPMask.sIpV4);
                }
                if (dns1 == null || dns1.isEmpty()) {
                    dns1 = new String(net_dvr_netcfg_v30.struDnsServer1IpAddr.sIpV4);
                }
                if (dns2 == null || dns2.isEmpty()) {
                    dns2 = new String(net_dvr_netcfg_v30.struDnsServer2IpAddr.sIpV4);
                }

                System.out.println("【IP地址】：" + new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIP.sIpV4));
                System.out.println("【多播组地址】：" + new String(net_dvr_netcfg_v30.struMulticastIpAddr.sIpV4));
                System.out.println("【报警管理主机】：" + new String(net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4) + "-->" + ip);
                System.out.println("【报警管理主机端口】：" + net_dvr_netcfg_v30.wAlarmHostIpPort + "-->" + port);
                System.out.println("【子网掩码】：" + new String(net_dvr_netcfg_v30.struEtherNet[0].struDVRIPMask.sIpV4) + "-->" + mask);
                System.out.println("【网关】：" + new String(net_dvr_netcfg_v30.struGatewayIpAddr.sIpV4) + "-->" + gateway);
                System.out.println("【首选DNS服务器】：" + new String(net_dvr_netcfg_v30.struDnsServer1IpAddr.sIpV4) + "-->" + dns1);
                System.out.println("【备选DNS服务器】：" + new String(net_dvr_netcfg_v30.struDnsServer2IpAddr.sIpV4) + "-->" + dns2);
                net_dvr_netcfg_v30.struAlarmHostIpAddr.sIpV4 = ip.getBytes();
                net_dvr_netcfg_v30.wAlarmHostIpPort = port;
                net_dvr_netcfg_v30.struGatewayIpAddr.sIpV4 = gateway.getBytes();
                net_dvr_netcfg_v30.struEtherNet[0].struDVRIPMask.sIpV4 = mask.getBytes();
                net_dvr_netcfg_v30.struDnsServer1IpAddr.sIpV4 = dns1.getBytes();
                net_dvr_netcfg_v30.struDnsServer2IpAddr.sIpV4 = dns2.getBytes();
                net_dvr_netcfg_v30.write();

                bRet = hCNetSDK.NET_DVR_SetDVRConfig(lUserID, HCNetSDK.NET_DVR_SET_NETCFG_V30, 0, lpOutBuffer, net_dvr_netcfg_v30.size());
                if (bRet) {
                    System.out.println("-------设置报警主机参数成功-------");
                    return true;
                } else {
                    System.out.println("-------设置报警主机参数失败-------");
                    return false;
                }
            } else {
                System.out.println("-------获取报警主机参数失败-------");
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * 设备撤防，设备注销
     *
     * @param
     */
    public static void logout() {

        if (lUserID > -1) {
            if (hCNetSDK.NET_DVR_Logout(lUserID)) {
                System.out.println("注销成功");
            }
        }


        return;
    }


}
