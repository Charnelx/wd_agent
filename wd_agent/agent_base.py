from abc import ABC, abstractmethod

class AgentBase(ABC):

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def stage_credentials(self):
        pass

    @abstractmethod
    def stage_encrypt(self):
        pass

    @abstractmethod
    def stage_upload(self):
        pass

    @abstractmethod
    def stage_delete(self):
        pass