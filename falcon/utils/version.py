from asyncio import FastChildWatcher
import re
SubVersionLiteral = "([0-9]+).([0-9]+).?([0-9]+)?$"
SubVersion = re.compile(SubVersionLiteral)

VersionOperator = "\^|~|>=|>|<|<=|="
VersionLiteral = "[0-9]+.[0-9]+.[0-9]+"
Patternstr = f"({VersionOperator})?\s*({VersionLiteral})\s*({VersionOperator})?\s*({VersionLiteral})?$"
Pattern = re.compile(Patternstr)


class ContractVersion:
    left_operator: str 
    right_operator: str 
    left_version: str 
    right_version: str 
    def __init__(self, version) -> None:
        m = Pattern.match(version)
        if m:
            self.left_operator, self.left_version, \
                self.right_operator, self.right_version = m.groups()
        else:
            assert False, f"{version} cannot be parsed correctly"
    
    def isLeftGT(self):
        assert self.left_operator
        return self.left_operator == ">"
    def isLeftGE(self):
        assert self.left_operator
        return self.left_operator == ">="
    def isLeftLT(self):
        assert self.left_operator
        return self.left_operator == "<"
    def isLeftLE(self):
        assert self.left_operator
        return self.left_operator == "<="
    
    def isRightGT(self):
        assert self.right_operator
        return self.right_operator == ">"
    def isRightGE(self):
        assert self.right_operator
        return self.right_operator == ">="
    def isRightLT(self):
        assert self.right_operator
        return self.right_operator == "<"
    def isRightLE(self):
        assert self.right_operator
        return self.right_operator == "<="

    def isExact(self):
        return self.left_operator == "^" and self.right_operator == None  and self.right_version == None 
    
    # @Return 1 if version1 > version2; 
    #          0 if version1 == version2 
    #          -1 if version1 < version2
    @staticmethod
    def _compareTwoVersion(version1, version2):
        m1 = SubVersion.match(version1)
        m2 = SubVersion.match(version2)
        assert m1, f"{version1} cannot be parsed correctly"
        assert m2, f"{version2} cannot be parsed correctly" 
        big1, middle1, minor1 = m1.groups() 
        big2, middle2, minor2 = m2.groups() 
        if int(big1) > int(big2):
            return 1
        elif int(big1) == int(big2):
            if int(middle1) > int(middle2):
                return 1
            elif int(middle1) == int(middle2):
                if minor1 is None:
                    minor1 = "0"
                if minor2 is None:
                    minor2 = "0"
                if int(minor1) > int(minor2):
                    return 1 
                if int(minor1) == int(minor2):
                    return 0
        return -1 

    def containVersion(self, _version):
        if self.isExact():
            return self.left_version == _version 
        else:
            a = self._compareTwoVersion(_version, self.left_version)
            if self.right_version:
                b = self._compareTwoVersion(_version, self.right_version)
                return False if (a == 0 and (self.isLeftLT() or self.isLeftGT())) or (b == 0 and (self.isRightLT() or self.isRightGT())) else  a*b < 0  
            else:
                if self.left_operator:
                    return a == 1 if self.isLeftGT() else a >= 0 if self.isLeftGE() else a == -1 if self.isLeftLT() else a <= 0 
                else:
                    return a == 0
    
    def __str__(self) -> str:
        result = ""
        if self.left_operator:
            result += self.left_operator
        if self.left_version:
            result += self.left_version + " "
        if self.right_operator:
            result += self.right_operator
        if self.right_version:
            result += self.right_version
        return result

def test():
    test_version = ">=0.4.0"
    cv = ContractVersion(version=test_version)
    print(cv)
    print(cv.containVersion("0.4.0"))

    test_version = ">=0.4.0 <0.6.0"
    cv = ContractVersion(version=test_version)
    print(cv)
    print(cv.containVersion("0.5.19"))



if __name__ == "__main__":
    test()