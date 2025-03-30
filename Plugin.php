<?php
/**
 * 禁止国外、港澳台IP访问，支持自定义IP黑名单
 * @package ProhibitIP
 * @author culturesun,HansJack
 * @version 1.2
 * @update: 2024.03.15
 * @link https://culturesun.site
 */
class ProhibitIP_Plugin implements Typecho_Plugin_Interface
{
    // 缓存检测结果（单位：秒）
    const CACHE_TIME = 3600;

    public static function activate()
    {
        // 更安全的钩子注册方式
        Typecho_Plugin::factory('Widget_Archive')->beforeRender = array(__CLASS__, 'prohibitIP');
        return "插件启用成功，请及时配置IP规则";
    }

    public static function deactivate()
    {
        return "插件已禁用";
    }

    public static function config(Typecho_Widget_Helper_Form $form)
    {
        // IP黑名单（自动去除空行和注释）
        $ips = new Typecho_Widget_Helper_Form_Element_Textarea(
            'ips',
            null,
            null,
            'IP黑名单',
            '每行一个IP，支持格式：<br>
            192.168.1.1<br>
            210.10.2.1-20<br>
            222.34.4.*<br>
            218.192.104.0/24'
        );
        $form->addInput($ips);

        // 跳转链接（自动添加http前缀校验）
        $location_url = new Typecho_Widget_Helper_Form_Element_Text(
            'location_url',
            null,
            'https://www.google.com/',
            '跳转地址',
            '需以http://或https://开头'
        );
        $location_url->addRule('url', '请输入合法URL地址');
        $form->addInput($location_url);
    }

    public static function personalConfig(Typecho_Widget_Helper_Form $form) {}

    public static function prohibitIP()
    {
        if (self::shouldBlock()) {
            self::safeRedirect();
        }
    }

    private static function safeRedirect()
    {
        try {
            $config = Typecho_Widget::widget('Widget_Options')->plugin('ProhibitIP');
            $url = $config->location_url ?? 'https://www.google.com/';
            
            // 强制清除会话
            Typecho_Cookie::delete('__typecho_uid');
            Typecho_Cookie::delete('__typecho_authCode');
            @session_destroy();
            
            header("Location: " . filter_var($url, FILTER_VALIDATE_URL));
            exit;
        } catch (Exception $e) {
            // 记录错误日志但不中断流程
            error_log("ProhibitIP Redirect Error: " . $e->getMessage());
        }
    }

    private static function shouldBlock()
    {
        $ip = self::getClientIP();
        
        // 缓存检测结果
        $cacheKey = 'prohibit_ip_' . md5($ip);
        if ($cached = Typecho_Cookie::get($cacheKey)) {
            return (bool)$cached;
        }

        $block = self::checkIPRules($ip) || self::checkGeoLocation($ip);
        Typecho_Cookie::set($cacheKey, $block ? '1' : '0', time() + self::CACHE_TIME);
        
        return $block;
    }

    private static function getClientIP()
    {
        $request = new Typecho_Request;
        return trim($request->getIp());
    }

    private static function checkIPRules($ip)
    {
        $patterns = self::getCompiledRules();
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $ip)) {
                return true;
            }
        }
        return false;
    }

    private static function getCompiledRules()
    {
        $config = Typecho_Widget::widget('Widget_Options')->plugin('ProhibitIP');
        $rules = [];
        
        if (!empty($config->ips)) {
            $lines = array_filter(
                explode("\n", $config->ips),
                function($line) {
                    $clean = trim($line);
                    return !empty($clean) && $clean[0] != '#';
                }
            );
            
            foreach ($lines as $line) {
                if ($pattern = self::ipToRegex(trim($line))) {
                    $rules[] = $pattern;
                }
            }
        }
        return $rules;
    }

    private static function ipToRegex($ipRule)
    {
        // 处理CIDR格式（如 192.168.1.0/24）
        if (strpos($ipRule, '/') !== false) {
            list($network, $prefix) = explode('/', $ipRule, 2);
            $ipLong = ip2long($network);
            $mask = ~((1 << (32 - $prefix)) - 1);
            $start = $ipLong & $mask;
            $end = $start | (~$mask);
            return '/^(' . long2ip($start) . '-' . long2ip($end) . ')$/';
        }

        // 转换通配符和范围
        $regex = str_replace(
            ['.', '*'],
            ['\\.', '\d+'],
            $ipRule
        );
        
        // 处理数字范围（如 192.168.1.1-20）
        $regex = preg_replace_callback('/(\d+)-(\d+)/', function($matches) {
            return '(' . implode('|', range($matches[1], $matches[2])) . ')';
        }, $regex);
        
        return '/^' . $regex . '$/';
    }

    private static function checkGeoLocation($ip)
    {
        // 改用本地IP库（需自行部署）
        // 此处保留原API调用作为示例，建议替换为MaxMind GeoLite2等方案
        
        $lang = strtolower($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
        $isChineseLang = strpos($lang, 'zh') !== false;

        try {
            $context = stream_context_create(['http' => ['timeout' => 2]]);
            $response = file_get_contents(
                "http://whois.pconline.com.cn/ipJson.jsp?json=true&ip={$ip}",
                false,
                $context
            );
            
            if ($response) {
                $data = json_decode(mb_convert_encoding(trim($response), 'UTF-8', 'GBK'), true);
                $proCode = $data['proCode'] ?? '';
                $isBlockedRegion = in_array($proCode, ['999999', '810000', '820000', '710000']);
                return $isBlockedRegion || !$isChineseLang;
            }
        } catch (Exception $e) {
            error_log("GeoAPI Error: " . $e->getMessage());
        }
        
        return !$isChineseLang; // API失败时仅依赖语言判断
    }
}
