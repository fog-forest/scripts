#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <admin@amogu.cn>
# @Date  : 2022/11/14
# @Desc  : 导出 MacCMS mac_vod 表对应字段词库

import pymysql

from main import MacCMS


class Word(MacCMS):

    def __init__(self, field):
        """
        :param field: mac_vod 中的字段
        """
        self.field = field

    def __select_field(self) -> tuple:
        """
        查询数据库字段

        :return: 查询结果
        """
        config = self.read_config()['db']
        db = pymysql.connect(host=config['host'], user=config['user'], password=config['password'],
                             database=config['database'])
        # 使用cursor()方法获取操作游标
        cursor = db.cursor()
        sql = 'SELECT %s FROM mac_vod GROUP BY %s' % (self.field, self.field)
        try:
            cursor.execute(sql)
            # 获取所有记录列表
            results = cursor.fetchall()
            return results
        except:
            print("Error: unable to fetch data")
        # 关闭数据库连接
        db.close()

    @classmethod
    def clean_up(cls, alist):
        """
        列表去重排序

        :param alist: 需整理的列表
        :return: 去重排序后的列表
        """
        temp_list = []
        for a in alist:
            for b in a.split(','):
                if b not in temp_list:
                    temp_list.append(b)
                else:
                    pass
        temp_list.sort()
        for word in temp_list:
            print(word)

    def replace_test(self):
        """
        同义词替换测试

        :return: 替换后的列表
        """
        temp_list = []  # 临时列表
        data = self.__select_field()
        # print(data)
        for a in data:
            # print(a)
            for b in a[0].split(','):
                # print(b)
                word_list = b.split(',')  # 以 ',' 分割相应字段字符串
                ''' 替换同义词开始 '''
                for word in word_list:  # 遍历词库
                    # print(word)
                    if word == '':  # 空字符设置为其他
                        word = '其他'
                    elif len(word) < 2:  # 过滤单字符
                        continue
                    else:
                        replace_word = self.read_config()['word'][self.field.replace('vod_', '')][0]  # 对应的替换同义词字典
                        # print(replace_word)
                        times = len(replace_word)  # 需替换的次数
                        for replace_num in range(times):
                            word = word.replace(list(replace_word.keys())[replace_num],
                                                list(replace_word.values())[replace_num])
                    # print(word)
                    temp_list.append(word)
                ''' 替换同义词结束 '''
        # 整理词库
        self.clean_up(temp_list)


if __name__ == '__main__':
    obj = Word('vod_class')  # vod_class,vod_area,vod_lang
    obj.replace_test()
