package CommonMethod;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * @author
 * @create 2022-03-22-11:13
 */
public class CommonUtil {

    // jar包之外的配置文件路径
    final static String CONFIG_PATH = "cfg/config.properties";
    // jar包内的配置文件路径
    final static String CONFIG_PATH_IN = "/cfg/config.properties";

    /**
     * 校验字符串是否为空
     */
    public static boolean isEmpty(final CharSequence string) {
        return string == null || string.length() == 0;
    }

    /**
     * 读取配置文件属性
     * 默认从jar包外读取
     * 读取失败时从jar包内读取
     * 读取失败时直接终止程序
     *
     * @param key
     * @return
     */
    public static String getProperty(String key) {
        return getProperty(false, key);
    }

    public static String getProperty(boolean inJar, String key) {
        String value = "";
        try {
            FileInputStream inputStream1 = new FileInputStream(inJar ? CONFIG_PATH_IN : CONFIG_PATH);
            // 输出路径
            Properties properties = new Properties();
            properties.load(inputStream1);
            value = properties.getProperty(key);
            // 为空时返回空字符串
            if (value == null) {
                value = "";
            }
        } catch (FileNotFoundException e) {
            System.err.println("找不到配置文件");
            e.printStackTrace();
            if (inJar) {
                // 直接终止程序
                System.exit(0);
            } else {
                return getProperty(true, key);
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("读取配置文件失败");
        }
        return value;
    }

}
