from models.base_class import FileMetadata

class BaseAnalysisClass:

    def processFile(self, file_object: FileMetadata):
        pass

    def postProcessFile(self, file_object: FileMetadata):
        pass

    def post_postProcessFile(self, file_object: FileMetadata):
        pass

    # For malicious file detection, we need to reprocess the file
    def reprocessFile(self, file_object: FileMetadata, r_data: str):
        pass
