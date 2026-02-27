#!/usr/bin/python3
# coding=utf8
# @Author: Kinoko <admin@amogu.cn>
# @Date  : 2022/11/14
# @Desc  : MacCMS 扩展分类&地区&语言词库自动整理合并
import os

import pymysql
import yaml


class MacCMS:

    @classmethod
    def read_config(cls) -> dict:
        """
        读取配置文件内容

        :return: 配置文件内容
        """
        # 获取yaml配置文件路径
        path = os.path.join(os.path.dirname(__file__), 'config.yml')
        with open(path, 'r', encoding='utf-8') as f:
            data = f.read()
        config = yaml.load(data, Loader=yaml.FullLoader)  # 转字典
        return config

    @classmethod
    def __select_db(cls) -> tuple:
        """
        查询数据库

        :return: 数据库查询结果（vod_id,vod_class,vod_area,vod_lang）
        """
        config = cls.read_config()['db']
        num = cls.read_config()['num']
        db = pymysql.connect(host=config['host'], user=config['user'], password=config['password'],
                             database=config['database'])
        # 使用cursor()方法获取操作游标
        cursor = db.cursor()
        # SQL 查询语句
        if num == 'all':
            sql = 'SELECT vod_id,vod_class,vod_area,vod_lang FROM mac_vod ORDER BY vod_id DESC'
        else:
            sql = 'SELECT vod_id,vod_class,vod_area,vod_lang FROM mac_vod ORDER BY vod_time DESC LIMIT ' + str(num)
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
    def update_db(cls, sql: str) -> None:
        """
        更新数据库

        :param sql: SQL语句
        :return: None
        """
        config = cls.read_config()['db']
        db = pymysql.connect(host=config['host'], user=config['user'], password=config['password'],
                             database=config['database'])
        # 使用cursor()方法获取操作游标
        cursor = db.cursor()
        try:
            # 执行SQL语句
            cursor.execute(sql)
            print(sql)
            # 提交到数据库执行
            db.commit()
        except:
            # 发生错误时回滚
            db.rollback()
        # 关闭数据库连接
        db.close()

    @classmethod
    def __replace_word(cls, data: tuple) -> str:
        """
        替换同义词

        :return: SQL语句
        """
        sql_param = []  # SQL更新参数列表 vod_class, vod_area, vod_lang
        replace_word_list = list(cls.read_config()['word'].values())
        # print(replace_word_list)
        for field_num in range(len(data)):  # 遍历传入字段
            save_list = []  # 最终词库列表
            temp_list = []  # 临时列表
            if field_num == 0:  # 剔除 vod_id 字段
                continue
            else:
                word_list = data[field_num].split(',')  # 以 ',' 分割相应字段字符串
                ''' 替换同义词开始 '''
                for word in word_list:  # 遍历词库
                    # print(word)
                    if word == '':  # 空字符设置为其他
                        word = '其他'
                    elif len(word) < 2:  # 过滤单字符
                        continue
                    else:
                        replace_word = replace_word_list[field_num - 1][0]  # 对应的同义词替换字典
                        # print(replace_word)
                        times = len(replace_word)  # 需替换的次数
                        for replace_num in range(times):
                            word = word.replace(list(replace_word.keys())[replace_num],
                                                list(replace_word.values())[replace_num])
                    temp_list.append(word)
                ''' 替换同义词结束 '''
            '''词库去重开始'''
            # print(temp_list)
            for a in temp_list:
                for b in a.split(','):
                    if b not in save_list:
                        save_list.append(b)
                    else:
                        pass
            sql_param.append(','.join(save_list))
            '''词库去重结束'''
        # 最终的SQL更新语句
        sql = 'UPDATE mac_vod SET vod_class="' + sql_param[0] + '",vod_area="' + sql_param[1] + '",vod_lang="' + \
              sql_param[2] + '" WHERE vod_id=' + str(data[0])
        return sql

    @classmethod
    def main(cls):
        result = cls.__select_db()
        for data in result:  # 遍历视频数据
            sql = cls.__replace_word(data)
            cls.update_db(sql)


if __name__ == "__main__":
    MacCMS.main()
    # 删除无图片的文章
    # MacCMS.update_db('DELETE FROM mac_art WHERE art_pic = ""')
    # 替换视频图片海报链接
    # MacCMS.update_db('UPDATE mac_vod SET vod_pic = REPLACE(vod_pic, "http://", "https://")')
