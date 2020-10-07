import logging

import yaml
from pathlib import Path


class Utils:

    @staticmethod
    def load_config(file_path):
        """Load config from yaml file

        Args:
            file_path (str): file path

        Raises:
            Exception: Exceptions

        Returns:
            dict: configs
        """

        try:
            with open(file_path, 'r') as fp:
                config = yaml.load(fp.read(), yaml.FullLoader)
                return config

        except Exception as e:
            raise Exception(e)

    @staticmethod
    def get_logger(logger_name):
        """
        Get logger
        :param logger_name: logger name
        :return: logger object
        """
        logging.basicConfig(filename=f'src/log/{logger_name}.log',
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.INFO)

        return logging.getLogger(logger_name)


if __name__ == '__main__':
    logger = Utils.get_logger('test')
    logger.info('aaaa')
