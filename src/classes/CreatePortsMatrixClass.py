from utils import *

class CreatePortsMatrix(object):
    '''
        CreatePortsMatrixClass:

    '''
    def __init__(self,
                 start_range:Union[int, None]=None,
                 end_range:Union[int, None]=None,
                 list_of_ports:Union[list, None]=None,
                 all_ports:Union[int, None]=None,
                 number_for_rand:Union[int, None]=None
                 ) -> NoReturn:

        if all(type( _ ) == None for _ in
               [start_range, end_range, all_ports, number_for_rand]):
            raise AssertionError


        self.start_range = start_range
        self.end_range = end_range
        self.list_of_ports = list_of_ports
        self.all_ports = all_ports
        self.number_for_rand = number_for_rand
        self.max_port_number = 65535

        if all(isinstance(_, int) for _ in [self.start_range, self.end_range]):
            self.total_number = self.end_range - self.start_range
        elif isinstance(self.all_ports, int):
            self.total_number = self.all_ports
        elif isinstance(self.number_for_rand, int):
            self.total_number = self.number_for_rand
        elif isinstance(self.list_of_ports, list):
            self.total_number = len(self.list_of_ports)
        else:
            raise ValueError

        if not (self.max_port_number + 1 > self.total_number > 0):
            raise ValueError

        if self.total_number <= 18:
            self.range_size = self.total_number
        elif 18 < self.total_number <= 4000:
            self.range_size = self.total_number // 18
        elif 4000 < self.total_number < 8000 :
            self.range_size = self.total_number // 40
        elif 8000 < self.total_number:
            self.range_size = self.total_number // 200


        # calculating number of lists to scan based on threads
        self.remainder = self.total_number % self.range_size
        self.part_size = (self.total_number - self.remainder) // self.range_size
        self.matrix = []

    def list_based_range(self) -> Sequence[list[list[int]]]:
        for _ in range(self.total_number):
            first_index = self.list_of_ports[_]
            tmp_list = []
            tmp_list.append(first_index)
            second_index = self.list_of_ports[_] + 1
            tmp_list.append(second_index)
            self.matrix.append(tmp_list)
        return self.matrix

    def number_based_range(self) -> Sequence[list[list[int]]]:
        # ranging for all ports or a number of random ports to scan
        first_index = 1
        for _ in range(1, self.part_size+1):
            tmp_list = list()
            tmp_list.append(first_index)
            second_index = (_ * self.range_size) + 1
            tmp_list.append (second_index)
            first_index = second_index
            self.matrix.append(tmp_list)

        # appenig the reminder
        if self.remainder:
            self.matrix.append([self.matrix[-1:][0][1],self.total_number + 1])

        return self.matrix

    def range_based_range(self) -> Sequence[list[list[int]]]:
        # ranging for a range of port to scan
        first_index = self.start_range

        for _ in range(1, self.part_size+1):
            tmp_list = []
            tmp_list.append(first_index)
            second_index = (_ * self.range_size) + self.start_range
            tmp_list.append (second_index)
            first_index += self.range_size
            self.matrix.append(tmp_list)

        # appending the reamander if any
        if self.remainder:
            self.matrix.append([self.matrix[-1:][0][1],self.end_range + 1])

        return self.matrix

    def __repr__(self) -> str:
        msg = f"""start range: {self.start_range} \nend range: {self.end_range}
        \nall of ports = {self.all_ports}\n port number count for random scan is
        {self.number_for_rand}\n class returns a matrix of port lists
        """
        return msg

    def __str__(self) -> str:
        msg = f"""start range: {self.start_range} \nend range: {self.end_range}
        \nall of ports = {self.all_ports}\n port number count for random scan is
        {self.number_for_rand}\n class returns a matrix of port lists
        """
        return msg

